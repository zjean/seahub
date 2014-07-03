# -*- coding: utf-8 -*-
import re

class BadGroupNameError(Exception):
    pass

class ConflictGroupNameError(Exception):
    pass

def validate_group_name(group_name):
    """
    Check whether group name is valid.
    A valid group name only contains alphanumeric character, and the length
    should less than 255.
    """
    if len(group_name) > 255:
        return False
    return re.match('^\w+$', group_name, re.U)

def get_group_dict():
    """Get a dict of a group: name for key, id for value.

    Returns:
    - `group_dict`: if have group(s).
        {
            'foo': 1,
            'bar': 2
         }

    - `None`: if have no groups.
    """
    from seaserv import ccnet_threaded_rpc
    all_groups = ccnet_threaded_rpc.get_all_groups(-1, -1)

    if all_groups:
        group_dict = {}
        for group in all_groups:
            group_dict[group.group_name] = group.id

        return group_dict
    else:
        return None
