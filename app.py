#!/usr/bin/env python3
import os

import aws_cdk as cdk

from pagerduty_workflow.pagerduty_workflow_stack import PagerdutyWorkflowStack


app = cdk.App()

PagerdutyWorkflowStack(app, "PagerdutyWorkflowStack",
    env=cdk.Environment(account='985936675960', region='us-west-2'),
)

app.synth()
