import requests
import yaml
import json
import boto3
import os
import traceback
from botocore.exceptions import ClientError

# Define the secret name
SECRET_NAME_PAGERDUTY_API_KEY = "pagerduty/API_KEY"
SECRET_NAME_SLACK_WEBHOOK = "pagerduty/SLACK_WEBHOOK"
REGION_NAME = os.environ.get("AWS_REGION")

session = boto3.session.Session()
secrets_client = session.client(service_name="secretsmanager", region_name=REGION_NAME)


def get_secret(secret_name):
    """Fetches a secret string from AWS Secrets Manager."""
    print(f"Attempting to retrieve secret: {secret_name}")

    try:
        get_secret_value_response = secrets_client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print("Secret not found")
        else:
            raise e
    else:
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
            return secret
        else:
            print("Secret not found")
            return None
    return None


API_KEY_JSON = get_secret(SECRET_NAME_PAGERDUTY_API_KEY)
API_KEY = json.loads(API_KEY_JSON)["API_KEY"]

SLACK_JSON = get_secret(SECRET_NAME_SLACK_WEBHOOK)
SLACK_WEBHOOK = json.loads(SLACK_JSON)["WEBHOOK"]

# Common headers for all API calls
HEADERS = {
    "Authorization": f"Token token={API_KEY}",
    "Accept": "application/vnd.pagerduty+json;version=2",
}

# Base API URL for PagerDuty
BASE_URL = "https://api.pagerduty.com"


# --- PagerDuty API Functions ---
def get_incident_alerts(incident_id):
    """Fetch alerts associated with an incident."""
    if not API_KEY:
        print("Error: PagerDuty API_KEY is not set.")
        return None
    url = f"{BASE_URL}/incidents/{incident_id}/alerts"
    params = {"limit": 100}
    try:
        response = requests.get(url, headers=HEADERS, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error fetching alerts for {incident_id}: {errh}")
        print(f"Response Body: {response.text}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Connection Error fetching alerts for {incident_id}: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error fetching alerts for {incident_id}: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"Error fetching alerts for {incident_id}: {err}")
    return None


# --- Alert Data Extraction Functions ---
def extract_alert_info(alert):
    """Extracts additional details from a single alert's body."""
    additional = {
        "incident_url": "N/A",
        "policy_url": "N/A",
        "severity": "N/A",
        "runbook_url": "N/A",
        "condition_name": "N/A",
        "details": "N/A",
    }
    details_source = {}

    # Dig into the alert body safely
    if "body" in alert and isinstance(alert["body"], dict):
        body = alert["body"]
        # First try from cef_details -> details
        cef_details = body.get("cef_details", {})
        if isinstance(cef_details, dict):
            details_source = cef_details.get("details", {})

        # Fallback to body["details"] if not found in cef_details
        if (
            not details_source
            and "details" in body
            and isinstance(body["details"], dict)
        ):
            details_source = body.get("details", {})
        # Handle case where body.details might be a string directly
        elif (
            not details_source
            and "details" in body
            and isinstance(body["details"], str)
        ):
            additional["details"] = body["details"]  # Assign directly if it's a string

    # Populate 'additional' dict from the found details_source
    for key in additional:
        # Only update if not already set (e.g., by direct string assignment above)
        # and if the key exists in details_source and has a non-None value
        if (
            additional[key] == "N/A"
            and key in details_source
            and details_source.get(key) is not None
        ):
            additional[key] = details_source.get(key)

    return additional


def find_values_by_key(data, target_key):
    """
    Recursively searches for ALL values associated with a specific key
    within a nested data structure. Uses DFS.

    Args:
        data: The dictionary or list to search within.
        target_key (str): The key whose values we are looking for.

    Returns:
        list: A list of all values (could be strings, lists, dicts, etc.)
              found associated with the target_key.
    """
    found_values = []

    def recurse(item):
        if isinstance(item, dict):
            for key, value in item.items():
                if key == target_key:
                    # Add the value regardless of its type
                    found_values.append(value)
                # Always recurse deeper into the value
                recurse(value)
        elif isinstance(item, list):
            for element in item:
                recurse(element)

    recurse(data)
    return found_values


# --- Function to Process Alerts with Filters ---
def process_alerts_with_filters(alerts, filters):
    """
    Processes alerts based on filter rules defined in the filters dictionary.
    Handles simple strings, lists of objects, and direct objects found via
    recursive search for filter-against keys.
    """
    final_tags = set()
    grouped_details = {}
    tag_added_flags = {filter_name: False for filter_name in filters}

    if not alerts:
        print("Warning: No alerts provided for processing.")
        return [], {}

    for filter_name, config in filters.items():
        condition = config.get("condition")
        condition_type = config.get("condition_type")
        filter_against_list = config.get(
            "filter-against", []
        )  # e.g., ["description", "contexts", "labels"]
        keys_to_match = config.get(
            "keys", []
        )  # e.g., ["Lytx.DeviceWake.Api", "href", "k8s.namespaceName"]
        tag = config.get("tag")

        if not all(
            [condition, condition_type, filter_against_list, keys_to_match, tag]
        ):
            print(f"Warning: Skipping filter '{filter_name}' due to missing config.")
            continue

        for alert in alerts:
            # Optimization: If tag already added for this filter, skip processing this alert *for this filter*
            # We only need to add the tag once per filter definition.
            # For fetch-output-with-tag, we might miss some key-values if we skip early.
            # Let's refine this: only skip if the tag is added AND it's an input-tag type.
            # For fetch-output, we need to gather all KVs.
            if tag_added_flags[filter_name] and condition_type == "input-tag":
                continue  # Already added this input-tag, move to next alert for this filter

            match_found_in_alert_for_filter = False

            for (
                field_to_search
            ) in filter_against_list:  # e.g., "description", "contexts", "labels"
                # Use the general recursive search
                found_values = find_values_by_key(alert, field_to_search)

                for value in found_values:  # Value could be str, list, dict, etc.

                    # --- Handle 'input-tag' ---
                    if condition_type == "input-tag":
                        # Case 1: Value is a string (e.g., found "description": "string")
                        if isinstance(value, str):
                            if condition == "contains":
                                for key in keys_to_match:
                                    if key in value:
                                        if not tag_added_flags[filter_name]:
                                            final_tags.add(tag)
                                            tag_added_flags[filter_name] = True
                                        match_found_in_alert_for_filter = True
                                        break  # Key matched in string
                        # Case 2: Value is a list (e.g., found "contexts": [...])
                        elif isinstance(value, list):
                            for item in value:
                                # Assume items in list are dicts we want to check keys in
                                if isinstance(item, dict):
                                    for key_to_find in keys_to_match:  # e.g., "href"
                                        if (
                                            key_to_find in item
                                        ):  # Check if key exists in the dict item
                                            if not tag_added_flags[filter_name]:
                                                final_tags.add(tag)
                                                tag_added_flags[filter_name] = True
                                            match_found_in_alert_for_filter = True
                                            break  # Key found in list item
                                if match_found_in_alert_for_filter:
                                    break  # Matched in list
                        # Add other type handlers if needed (e.g., dict directly for input-tag?)

                    # --- Handle 'fetch-output-with-tag' ---
                    elif condition_type == "fetch-output-with-tag":
                        objects_to_process = []
                        # Case 1: Value is a dictionary (e.g., found "labels": {...})
                        if isinstance(value, dict):
                            objects_to_process.append(value)
                        # Case 2: Value is a list (e.g., found "contexts": [...] or "targets": [...])
                        elif isinstance(value, list):
                            for item in value:
                                # Add dictionary items from the list to be processed
                                if isinstance(item, dict):
                                    objects_to_process.append(item)

                        # Process the collected dictionary objects
                        for obj in objects_to_process:
                            for (
                                key_to_extract
                            ) in keys_to_match:  # e.g., "href", "k8s.namespaceName"
                                if key_to_extract in obj:
                                    # Add tag if not already added for this filter
                                    if not tag_added_flags[filter_name]:
                                        final_tags.add(tag)
                                        tag_added_flags[filter_name] = True

                                    # Initialize list for the tag if needed
                                    grouped_details.setdefault(tag, [])
                                    # Format and add the key-value string if not present
                                    detail_string = (
                                        f"{key_to_extract} = {obj[key_to_extract]}"
                                    )
                                    if detail_string not in grouped_details[tag]:
                                        grouped_details[tag].append(detail_string)
                                    # We found a key to extract, but don't set match_found_in_alert_for_filter
                                    # because we need to potentially extract *multiple* keys from this object
                                    # and check other objects/values found for this field_to_search.

                    # Break from iterating through found_values if a match added the tag (for input-tag)
                    if (
                        match_found_in_alert_for_filter
                        and condition_type == "input-tag"
                    ):
                        break
                # Break from iterating through filter_against_list if a match added the tag (for input-tag)
                if match_found_in_alert_for_filter and condition_type == "input-tag":
                    break

    return list(final_tags), grouped_details


def send_slack_output(slack_output_dict, SLACK_WEBHOOK):
    match_details = slack_output_dict.get("details", {})
    final_tags = slack_output_dict.get("tags", set())

    # Incident details with fallback
    incident_url = match_details.get("incident_url", "N/A")
    policy_url = match_details.get("policy_url", "N/A")
    severity = match_details.get("severity", "N/A")
    runbook_url = match_details.get("runbook_url", "N/A")
    condition_name = match_details.get("condition_name", "N/A")
    description = match_details.get("details", "N/A")

    # Build the message block
    lines = []

    # Visual separation & header
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"*🟢 PAGERDUTY ALERT TRIGGERED:* `{description}`")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # Core incident info
    lines.append(f"*📌 INCIDENT URL*: <{incident_url}>")
    lines.append(f"*📄 POLICY URL*  : <{policy_url}>")
    lines.append(f"*🚨 SEVERITY*    : `[{severity}]`")
    lines.append(f"*🧠 CONDITION*   : `{condition_name}`")
    lines.append("")

    # Tag matches
    lines.append("*🎯 Tag Matches:*")
    if final_tags:
        for tag in sorted(final_tags):
            lines.append(f"> *🏷️ Tag:* `[{tag}]`")
            for item in match_details.get(tag, []):
                lines.append(f"> • {item}")
            lines.append("")  # spacing between tag blocks
    else:
        lines.append("> _No tag matches found._")

    # Runbook
    lines.append(f"*📘 RUNBOOK URL* : <{runbook_url}>")

    # Final payload
    payload = {"text": "\n".join(lines)}

    try:
        response = requests.post(SLACK_WEBHOOK, json=payload)
        if response.status_code == 200:
            print("✅ Slack message sent successfully.")
        else:
            print(
                f"❌ Failed to send Slack message. Status: {response.status_code}, Response: {response.text}"
            )
    except Exception as e:
        print(f"⚠️ Error sending Slack message: {e}")


# --- Main Execution Logic ---
def lambda_handler(event, context):
    # --- Select Incident ID ---
    # incident_id = "Q0WVUWIXVOP2A8"  # Kafka example
    # incident_id = "Q0J4J46HFZRNHF"   # Windows alert example
    # incident_id = "Q3NERHR7A7W9H4"  # k8s alert example
    # incident_id = "Q16HWF43U1YMGP" # No tag match example
    # incident_id = "Q06VIQYR27094T" # Another example

    print("Received event:", json.dumps(event))

    # Basic check if required env vars are set
    if not API_KEY or not SLACK_WEBHOOK:
        print(
            "Error: Required environment variables PAGERDUTY_API_KEY or SLACK_WEBHOOK_URL not configured."
        )
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Internal configuration error"}),
        }

    print(f"Attempting to process incident...")

    try:

        # 1. Check if 'body' exists and is not empty
        if "body" not in event or not event["body"]:
            print("Error: Event body is missing or empty.")
            return {
                "statusCode": 400,  # Bad Request
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Request body is missing or empty."}),
            }

        # 2. Parse the JSON string from the event body
        body_data = json.loads(event["body"])
        print("Parsed body data:", json.dumps(body_data))  # Log parsed data

        # 3. Check if 'incident.url' key exists in the parsed body
        if "incident.url" not in body_data:
            print("Error: 'incident.url' key not found in body.")
            return {
                "statusCode": 400,  # Bad Request
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(
                    {"error": "'incident.url' missing in request body."}
                ),
            }

        incident_url = body_data["incident.url"]
        print(f"Found incident URL: {incident_url}")

        # 4. Extract the ID (last part of the URL path)
        if incident_url and isinstance(incident_url, str) and "/" in incident_url:
            # Split the URL by '/' and get the last element
            url_parts = incident_url.split("/")
            potential_id = url_parts[-1]  # Gets the last part

            # Basic validation: Ensure it's not empty
            if potential_id:
                incident_id = potential_id
                print(f"Successfully extracted Incident ID: {incident_id}")
            else:
                print(f"Error: Extracted empty incident ID from URL: {incident_url}")
        else:
            # Handle cases where the URL is missing, not a string, or has no '/'
            print(
                f"Error: Invalid or unexpected format for incident URL: {incident_url}"
            )

        # 5. Check if we successfully got the ID
        if not incident_id:
            # Return an error if extraction failed
            return {
                "statusCode": 400,  # Bad Request
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(
                    {"error": "Failed to extract valid incident ID from URL."}
                ),
            }

        print(f"Using Incident ID: {incident_id} for processing...")

        # --- Load Filters ---
        filters_file = "filters.yaml"
        filters = None
        if os.path.exists(filters_file):
            try:
                with open(filters_file, "r") as f:
                    filters = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"Error loading YAML file '{filters_file}': {e}")
                return
            except FileNotFoundError:
                print(f"Error: Filters file '{filters_file}' not found.")
                return
        else:
            print(f"Error: Filters file '{filters_file}' not found.")
            return

        if not filters:
            print("Filters could not be loaded. Exiting.")
            return

        # --- Retrieve Alerts ---
        print(f"Fetching alerts for incident ID: {incident_id}")
        alerts_data = get_incident_alerts(incident_id)

        if alerts_data is None or "alerts" not in alerts_data:
            print("Failed to retrieve alerts data or no alerts found.")
            return

        alerts = alerts_data.get("alerts", [])
        if not alerts:
            print("No alerts found for this incident.")
            return

        # --- Process Alerts ---
        print("Processing alerts with filters...")
        # Get tags and the dictionary grouped by tags
        final_tags, grouped_key_value_details = process_alerts_with_filters(
            alerts, filters
        )

        # --- Extract Additional Info (from the first alert) ---
        # Assumes the most relevant general details are in the first alert
        additional_details = extract_alert_info(alerts[0])

        # --- Combine Results into Final Structure ---
        final_details_section = (
            grouped_key_value_details.copy()
        )  # Start with tag-grouped KeyValues
        final_details_section.update(
            additional_details
        )  # Add/overwrite with general details

        final_output = {"tags": final_tags, "details": final_details_section}

        send_slack_output(final_output, SLACK_WEBHOOK)

        # --- Print Final JSON Output ---
        # print("\n--- Final JSON Output ---")
        # print(json.dumps(final_output, indent=4))
        # print("-------------------------\n")

        # --- SUCCESS RESPONSE ---
        # Return a successful response to API Gateway
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
            },
            # Return relevant info, like the tags generated or just a success message
            "body": json.dumps(
                {
                    "message": "Incident processed successfully and notification sent.",
                }
            ),
        }

    except Exception as e:
        # Catch any unexpected errors during execution
        print(f"An unexpected error occurred: {e}")
        print(traceback.format_exc())

        # Return a generic server error response
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "An internal server error occurred."}),
        }
