# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import json

from c7n.exceptions import PolicyValidationError


class StructureParser:
    """Provide fast validation and inspection of a policy file.

    Intent is to provide more humane validation for top level errors
    instead of printing full schema as error message.
    """
    allowed_file_keys = {'vars', 'policies'}
    required_policy_keys = {'name', 'resource'}
    allowed_policy_keys = {'name', 'resource', 'title', 'description', 'mode',
         'tags', 'max-resources', 'metadata', 'query',
         'filters', 'actions', 'source', 'conditions',
         # legacy keys subject to deprecation.
         'region', 'start', 'end', 'tz', 'max-resources-percent',
         'comments', 'comment'}

    def validate(self, data):
        if not isinstance(data, dict):
            raise PolicyValidationError((
                "Policy file top level data structure "
                "should be a mapping/dict, instead found:%s") % (
                    type(data).__name__))
        dkeys = set(data.keys())

        if extra := dkeys.difference(self.allowed_file_keys):
            raise PolicyValidationError(
                f"Policy files top level keys are {', '.join(self.allowed_file_keys)}, found extra: {', '.join(extra)}"
            )


        if 'policies' not in data:
            raise PolicyValidationError("`policies` list missing")

        pdata = data.get('policies', [])
        if not isinstance(pdata, list):
            raise PolicyValidationError(
                f'`policies` key should be an array/list found: {type(pdata).__name__}'
            )

        for p in pdata:
            self.validate_policy(p)

    def validate_policy(self, p):
        if not isinstance(p, dict):
            raise PolicyValidationError((
                'policy must be a dictionary/mapping found:%s policy:\n %s' % (
                    type(p).__name__, json.dumps(p, indent=2))))
        pkeys = set(p)
        if self.required_policy_keys.difference(pkeys):
            raise PolicyValidationError(
                'policy missing required keys (name, resource) data:\n %s' % (
                    json.dumps(p, indent=2)))
        if pkeys.difference(self.allowed_policy_keys):
            raise PolicyValidationError(
                f"policy:{p['name']} has unknown keys: {','.join(pkeys.difference(self.allowed_policy_keys))}"
            )

        if not isinstance(p.get('filters', []), (list, type(None))):
            raise PolicyValidationError(
                f"policy:{p['name']} must use a list for filters found:{type(p['filters']).__name__}"
            )

        element_types = (dict, str)
        for f in p.get('filters', ()):
            if not isinstance(f, element_types):
                raise PolicyValidationError(
                    f"policy:{p.get('name', 'unknown')} filter must be a mapping/dict found:{type(f).__name__}"
                )

        if not isinstance(p.get('actions', []), (list, type(None))):
            raise PolicyValidationError(
                f"policy:{p.get('name', 'unknown')} must use a list for actions found:{type(p['actions']).__name__}"
            )

        for a in p.get('actions', ()):
            if not isinstance(a, element_types):
                raise PolicyValidationError(
                    f"policy:{p.get('name', 'unknown')} action must be a mapping/dict found:{type(a).__name__}"
                )

    def get_resource_types(self, data):
        resources = set()
        for p in data.get('policies', []):
            rtype = p['resource']
            if '.' not in rtype:
                rtype = f'aws.{rtype}'
            resources.add(rtype)
        return resources
