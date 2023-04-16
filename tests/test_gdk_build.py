# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the gdk_build.py script
"""
import runpy
import pytest

NAME = 'FooBar'
VERSION = 'rubbish'

DIRECTORY_ARTIFACTS = 'artifacts/'
DIRECTORY_BUILD = 'greengrass-build/artifacts/'
FILE_RECIPE_TEMPLATE = 'recipe.yaml'
FILE_RECIPE = 'greengrass-build/recipes/recipe.yaml'
FILE_ZIP_BASE = 'certificate-rotator'
FILE_ZIP_EXT = 'zip'

def recipe(name, version):
    """ Create a recipe string fragment """
    recipe_str =\
    f"""
    {{
    "ComponentName": "{name}",
    "ComponentVersion": "{version}"
    }}
    """

    return recipe_str


@pytest.fixture(name='gdk_config')
def fixture_gdk_config(mocker):
    """ Mock the GDK config """
    gdk_config_class = mocker.patch('libs.gdk_config.GdkConfig')
    gdk_config = gdk_config_class.return_value
    gdk_config.name.return_value = NAME
    gdk_config.version.return_value = VERSION

    yield gdk_config

    gdk_config_class.assert_called_once()

@pytest.fixture(name='file')
def fixture_file(mocker):
    """ Mock the file handling """
    m = m_recipe_template = mocker.mock_open(read_data=recipe('COMPONENT_NAME', 'COMPONENT_VERSION'))
    m_recipe = mocker.mock_open()
    m.side_effect=[m_recipe_template.return_value, m_recipe.return_value, m_recipe.return_value]
    file = mocker.patch('builtins.open', m)

    yield file

    file.assert_any_call(FILE_RECIPE_TEMPLATE, encoding="utf-8")
    file.assert_any_call(FILE_RECIPE, 'w', encoding="utf-8")

def test_specific_version(mocker, gdk_config, file):
    """ Confirm GDK build correctly assembles the recipe and the archive when version is specified in GDK config """
    make_archive = mocker.patch('shutil.make_archive')
    runpy.run_module('gdk_build')

    recipe_str = recipe(NAME, VERSION)
    file().write.assert_called_once_with(recipe_str)
    archive_name = DIRECTORY_BUILD + NAME + '/' + VERSION + '/' + FILE_ZIP_BASE
    make_archive.assert_called_once_with(archive_name, FILE_ZIP_EXT, DIRECTORY_ARTIFACTS)
    assert gdk_config.name.call_count == 2
    assert gdk_config.version.call_count == 3

def test_next_patch(mocker, gdk_config, file):
    """ Confirm GDK build correctly assembles the recipe and the archive when NEXT_PATCH is specified in GDK config """
    make_archive = mocker.patch('shutil.make_archive')
    gdk_config.version.return_value = 'NEXT_PATCH'
    runpy.run_module('gdk_build')

    recipe_str = recipe(NAME, 'COMPONENT_VERSION')
    file().write.assert_called_once_with(recipe_str)
    archive_name = DIRECTORY_BUILD + NAME + '/NEXT_PATCH/' + FILE_ZIP_BASE
    make_archive.assert_called_once_with(archive_name, FILE_ZIP_EXT, DIRECTORY_ARTIFACTS)
    assert gdk_config.name.call_count == 2
    assert gdk_config.version.call_count == 2
