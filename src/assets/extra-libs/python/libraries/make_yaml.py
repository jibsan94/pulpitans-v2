import os
import yaml

def generate_build_yaml(selected_role, output_path, form_data):
    vars_data = {}

    # Branch Name -> gitrepo_version (always included if not empty)
    if form_data.get('branch_name', '').strip():
        vars_data['idas_tool_mkbuild_gitrepo_version'] = form_data['branch_name'].strip()

    # GitRepo Local Dir -> only if text was written
    if form_data.get('gitrepo_local_dir', '').strip():
        vars_data['idas_tool_mkbuild_gitrepo_local_dir'] = form_data['gitrepo_local_dir'].strip()

    # MkBuild Project -> only if text was written
    if form_data.get('mkbuild_project', '').strip():
        vars_data['idas_tool_mkbuild_project'] = form_data['mkbuild_project'].strip()

    # Radio options -> only if not disabled
    radio_fields = {
        'gitrepo_update':   'idas_tool_mkbuild_gitrepo_update',
        'gitrepo_checkitc': 'idas_tool_mkbuild_gitrepo_checkitc',
        'gitrepo_git2cc':   'idas_tool_mkbuild_gitrepo_git2cc',
        'idasrpm_build':    'idas_tool_mkbuild_idasrpm_build',
        'idasrepo_build':   'idas_tool_mkbuild_idasrepo_build',
        'idasbuild_build':  'idas_tool_mkbuild_idasbuild_build',
    }

    for field_key, yaml_key in radio_fields.items():
        value = form_data.get(field_key, 'disabled')
        if value == 'true':
            vars_data[yaml_key] = True
        elif value == 'false':
            vars_data[yaml_key] = False
        # if disabled -> skip, don't add to vars

    build_data = [{
        'hosts': 'localhost',
        'connection': 'local',
        'vars': vars_data,
        'roles': [selected_role]
    }]

    with open(output_path, 'w') as f:
        f.write('---\n')
        yaml.dump(build_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return output_path