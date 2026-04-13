import os
import yaml

def generate_build_yaml(selected_role, output_path):
    """
    Generates a build.yaml file with the given role.
    Returns the output path if successful, raises an exception if not.
    """
    build_data = [{
        'hosts': 'localhost',
        'connection': 'local',
        'vars': {
            'idas_tool_mkbuild_gitrepo_version': 'icas-lvnl_jjrosat',
            'idas_tool_mkbuild_gitrepo_checkitc': True
        },
        'roles': [selected_role]
    }]

    with open(output_path, 'w') as f:
        f.write('---\n')
        yaml.dump(build_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return output_path