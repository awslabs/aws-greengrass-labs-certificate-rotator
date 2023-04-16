# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
API for the GDK configuration file
"""

import json
import os

class GdkConfig():
    """ API for the GDK configuration file """

    GDK_CONFIG_JSON = f'{os.path.dirname(os.path.abspath(__file__))}/../gdk-config.json'

    def __init__(self):
        """ Gets the GDK configuration file as a dictionary """
        with open(self.GDK_CONFIG_JSON, encoding="utf-8") as gdk_config_file:
            self.json = json.load(gdk_config_file)
            self.component_name = list(self.json['component'])[0]

    def name(self):
        """ Gets the component name from the GDK configuration """
        return self.component_name

    def version(self):
        """ Gets the component version from the GDK configuration """
        return self.json['component'][self.component_name]['version']

    def region(self):
        """ Gets the component region from the GDK configuration """
        return self.json['component'][self.component_name]['publish']['region']
