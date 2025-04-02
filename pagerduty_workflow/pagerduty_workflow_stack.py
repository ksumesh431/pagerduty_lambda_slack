from aws_cdk import (
    Stack,
    Tags,
    CfnOutput,
    Duration,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_apigateway as apigateway,
)
from constructs import Construct


class PagerdutyWorkflowStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Apply the tag to the Stack ---
        Tags.of(self).add("createdby", "CDK")
        Tags.of(self).add("project", "pagerduty_workflow")

        # IAM role for Lambda
        role = iam.Role(
            self,
            "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "SecretsManagerReadWrite"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "CloudWatchFullAccessV2"
                ),
            ],
        )

        # --- Define the Lambda Layer ---
        dependencies_layer = lambda_.LayerVersion(
            self,
            "PagerdutyDependenciesLayer",
            # Tell CDK where to find the layer code
            # CDK will zip the *contents* of this directory
            code=lambda_.Code.from_asset("lambda_layer_deps"),
            # Specify compatible runtimes. MUST match your function's runtime.
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_13],
            description="Layer containing requests and PyYAML dependencies",
        )

        # Lambda function (code in lambda_code directory)
        lambda_function = lambda_.Function(
            self,
            "Pagerduty_Workflow",
            runtime=lambda_.Runtime.PYTHON_3_13,
            code=lambda_.Code.from_asset("lambda_code"),
            handler="index.lambda_handler",
            role=role,
            layers=[dependencies_layer],
            timeout=Duration.seconds(10)
        )

        # API Gateway REST API
        api = apigateway.RestApi(self, "PagerdutyWorkflowApi")

        # Define API Gateway resources and methods
        api_resource = api.root.add_resource("pagerduty")

        # Add POST method
        api_resource.add_method(
            "POST",
            apigateway.LambdaIntegration(lambda_function),
            method_responses=[{"statusCode": "200"}],
        )

        # Output the API endpoint URL
        CfnOutput(
            self,
            "ApiEndpointUrl",
            value=f"{api.url}pagerduty",
            description="The endpoint URL for the PagerDuty workflow POST method",
        )
