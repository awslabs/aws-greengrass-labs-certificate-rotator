# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Custom build script for GDK component build operation. This script is not designed to
be executed directly. It is designed to be used by GDK.

Example execution:
gdk component build
"""

import shutil
from libs.gdk_config import GdkConfig

DIRECTORY_ARTIFACTS = 'artifacts/'
DIRECTORY_BUILD = 'greengrass-build/artifacts/'
FILE_RECIPE_TEMPLATE = 'recipe.yaml'
FILE_RECIPE = 'greengrass-build/recipes/recipe.yaml'
FILE_ZIP_BASE = 'certificate-rotator'
FILE_ZIP_EXT = 'zip'


def create_recipe():
    """ Creates the component recipe """
    print(f'Creating recipe {FILE_RECIPE}')

    with open(FILE_RECIPE_TEMPLATE, encoding="utf-8") as recipe_template_file:
        recipe_str = recipe_template_file.read()

    recipe_str = recipe_str.replace('COMPONENT_NAME', gdk_config.name())
    if gdk_config.version() != 'NEXT_PATCH':
        recipe_str = recipe_str.replace('COMPONENT_VERSION', gdk_config.version())

    with open(FILE_RECIPE, 'w', encoding="utf-8") as recipe_file:
        recipe_file.write(recipe_str)

    print('Created recipe')

def create_artifacts():
    """ Creates the artifacts archive as a ZIP file """
    file_name = DIRECTORY_BUILD + gdk_config.name() + '/' + gdk_config.version() + '/' + FILE_ZIP_BASE
    print(f'Creating artifacts archive {file_name}')
    shutil.make_archive(file_name, FILE_ZIP_EXT, DIRECTORY_ARTIFACTS)
    print('Created artifacts archive')


gdk_config = GdkConfig()

create_recipe()
create_artifacts()
