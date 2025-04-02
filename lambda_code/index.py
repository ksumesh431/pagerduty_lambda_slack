import requests
import yaml
import json
import boto3
import os
import traceback
from botocore.exceptions import ClientError


# incident_id = "Q0WVUWIXVOP2A8"   #Kafka
# incident_id = "Q0J4J46HFZRNHF"   # windows alert
# incident_id = "Q3NERHR7A7W9H4"  #k8s alert
# incident_id = "Q16HWF43U1YMGP"  # no tag match
# incident_id = "Q06VIQYR27094T"


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

PAGERDUTY_JSON = get_secret(SECRET_NAME_SLACK_WEBHOOK)
SLACK_WEBHOOK = json.loads(PAGERDUTY_JSON)["WEBHOOK"]

# Common headers for all API calls
HEADERS = {
    "Authorization": f"Token token={API_KEY}",
    "Accept": "application/vnd.pagerduty+json;version=2",
}

# Base API URL for PagerDuty
BASE_URL = "https://api.pagerduty.com"


def get_incident(incident_id):

    url = f"{BASE_URL}/incidents/{incident_id}"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.json()  # Parsed incident JSON
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Connection Error: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"Error: {err}")
    return None


def get_incident_alerts(incident_id):
    """
    Fetch alerts associated with an incident.
    """
    url = f"{BASE_URL}/incidents/{incident_id}/alerts"
    params = {"limit": 100}  # Adjust as needed.
    try:
        response = requests.get(url, headers=HEADERS, params=params)
        response.raise_for_status()
        return response.json()  # Parsed alerts JSON
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Connection Error: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"Error: {err}")
    return None


def load_filters(file_path):
    """
    Load and return filtering configuration from a YAML file.
    """
    try:
        with open(file_path, "r") as stream:
            filters = yaml.safe_load(stream)
        return filters
    except FileNotFoundError:
        print(f"The file {file_path} was not found.")
    except yaml.YAMLError as ye:
        print("Error parsing YAML file:", ye)
    return None


def extract_alert_info(alert):
    labels_collected = {}
    # Include new fields
    additional = {
        "incident_url": "N/A",
        "policy_url": "N/A",
        "severity": "N/A",
        "runbook_url": "N/A",
        "condition_name": "N/A",
        "details": "N/A",
    }
    details = {}

    # Dig into the alert body safely
    if "body" in alert and isinstance(alert["body"], dict):
        body = alert["body"]
        # print(json.dumps(body, indent=4))
        # First try from cef_details -> details
        cef_details = body.get("cef_details", {})
        if isinstance(cef_details, dict):
            details = cef_details.get("details", {})

        # Fallback to body["details"] if not found
        if not details and "details" in body:
            details = body.get("details", {})

    # Collect labels from targets list (inside details)
    targets = details.get("targets", [])
    if isinstance(targets, list):
        for target in targets:
            target_labels = target.get("labels", {})
            if isinstance(target_labels, dict):
                labels_collected.update(target_labels)

    # Extract all additional fields (old + new)
    for key in additional:
        if key in details and details.get(key) is not None:
            additional[key] = details.get(key)
    # print(additional)
    return labels_collected, additional


def process_filters_details(incident, alerts_info, filters):
    final_tags = set()
    match_details = {}

    # Process "input-tag" filters using incident fields dynamically
    # print(json.dumps(incident, indent=4))
    for filt in filters.values():
        if filt.get("condition_type") == "input-tag":
            cond = filt.get("condition")
            against = filt.get("filter-against", [])
            values = filt.get("values", [])
            tag = filt.get("tag")
            matched_values = []

            for field in against:
                incident_value = incident.get(field, "")
                if cond == "contains" and isinstance(incident_value, str):
                    for value in values:
                        if value in incident_value:
                            matched_values.append(value)

            if matched_values:
                final_tags.add(tag)
                match_details[tag] = list(set(matched_values))

    # Process "fetch-output-with-tag" filters over all alerts
    for filt in filters.values():
        if filt.get("condition_type") == "fetch-output-with-tag":
            cond = filt.get("condition")
            values = filt.get("values", [])
            tag = filt.get("tag")
            matched_items = []

            if cond == "contains":
                for alert_info in alerts_info:
                    # print(json.dumps(alerts_info, indent=4))
                    labels = alert_info.get("labels", {})
                    for label_key, label_value in labels.items():
                        for fval in values:
                            if fval in label_key:
                                matched_items.append(f"{label_key} = {label_value}")
            if matched_items:
                final_tags.add(tag)
                match_details[tag] = list(set(matched_items))

    # Pull incident metadata from the first alert_info dict (if present)
    alert_source = alerts_info[0] if alerts_info else {}

    # Metadata keys to extract
    meta_keys = [
        "incident_url",
        "policy_url",
        "severity",
        "runbook_url",
        "condition_name",
        "details",
    ]

    for key in meta_keys:
        match_details[key] = alert_source.get(
            key, f"Pagerduty incident missing value for {key}"
        )

    return final_tags, match_details


def pretty_print_output(match_details, final_tags):

    # Create the slack_output_dict
    slack_output_dict = {"tags": final_tags, "details": match_details}

    return slack_output_dict


def format_output_for_slack(slack_output_dict):
    output_lines = []

    # Extract data
    match_details = slack_output_dict.get("details", {})
    final_tags = slack_output_dict.get("tags", set())

    # Get main incident details
    incident_url = match_details.get(
        "incident_url", "Pagerduty incident missing value for incident_url"
    )
    policy_url = match_details.get(
        "policy_url", "Pagerduty incident missing value for policy_url"
    )
    severity = match_details.get(
        "severity", "Pagerduty incident missing value for severity"
    )
    runbook_url = match_details.get(
        "runbook_url", "Pagerduty incident missing value for runbook_url"
    )
    condition_name = match_details.get(
        "condition_name", "Pagerduty incident missing value for condition_name"
    )
    description = match_details.get(
        "details", "Pagerduty incident missing value for alert details"
    )

    # Alert description at the top as heading
    output_lines.append(f"{description}")
    output_lines.append("-" * 60)

    # Header section
    output_lines.append(f"[INCIDENT URL]    : {incident_url}")
    output_lines.append(f"[POLICY URL]      : {policy_url}")
    output_lines.append(f"[SEVERITY]        : {severity}")
    output_lines.append(f"[CONDITION NAME]  : {condition_name}")
    output_lines.append("-" * 60)

    # Tag match section
    if final_tags:
        output_lines.append("Tag Matches:")
        for tag in sorted(final_tags):
            output_lines.append(f"  [Tag: {tag}]")
            matched_items = match_details.get(tag, [])
            for item in matched_items:
                output_lines.append(f"    - {item}")
            output_lines.append("-" * 30)
    else:
        output_lines.append("No tag matches found.")
        output_lines.append("-" * 30)

    # Runbook section
    output_lines.append(f"[RUNBOOK URL]     : {runbook_url}")

    return "\n".join(output_lines)


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


def lambda_handler(event, context):

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

        # Retrieve the incident data.
        incident_data = get_incident(incident_id)
        if incident_data is None or "incident" not in incident_data:
            print("No incident data retrieved.")
            return
        incident = incident_data["incident"]

        # Retrieve alerts for the incident.
        alerts_data = get_incident_alerts(incident_id)
        if alerts_data is None or "alerts" not in alerts_data:
            print("No alerts data retrieved.")
            return
        alerts = alerts_data.get("alerts", [])

        # Extract alert info from each alert (labels & additional details).
        all_alerts_info = []
        for alert in alerts:
            alert_id = alert.get("id", "N/A")
            labels, additional_details = extract_alert_info(alert)

            alert_info = {
                "alert_id": alert_id,
                "labels": labels,
                "incident_url": additional_details.get("incident_url", "N/A"),
                "policy_url": additional_details.get("policy_url", "N/A"),
                "severity": additional_details.get("severity", "N/A"),
                "runbook_url": additional_details.get("runbook_url", "N/A"),
                "condition_name": additional_details.get("condition_name", "N/A"),
                "details": additional_details.get("details", "N/A"),
            }

            all_alerts_info.append(alert_info)

        # print(all_alerts_info)
        # Load filters from the YAML file.
        filters_file_path = "filters.yaml"
        filters = load_filters(filters_file_path)
        if not filters:
            print("No filters loaded.")
            return

        # Process filters and get final tag set along with match details.
        final_tags, match_details = process_filters_details(
            incident, all_alerts_info, filters
        )

        # Print the output in a beautiful, presentable format.
        slack_output = pretty_print_output(match_details, final_tags)
        slack_message = format_output_for_slack(slack_output)
        print(slack_message)
        send_slack_output(slack_output, SLACK_WEBHOOK)

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
