import ast
import fnmatch
from typing import Tuple


def role_mapping(filter_str: str, member_of: str) -> Tuple[list, int]:
    priority = 0
    try:
        mapping_groups = filter_str.strip().split('|')
        for g in mapping_groups:
            str_and_role = g.strip().split(':')
            if len(str_and_role) > 2:
                raise ValueError('Using multiple ":" characters in one group of mapping')
            elif len(str_and_role) == 1:
                return ast.literal_eval(str_and_role[0]), priority
            else:
                if fnmatch.fnmatchcase(member_of, str_and_role[0].strip("'").strip('"')):
                    return ast.literal_eval(str_and_role[1]), priority
            priority += 1
    except Exception as e:
        raise ValueError(f'Invalid string for mapping roles: {str(e)}')
    return [], priority


def stream_mapping(filter_str: str, member_of: str) -> Tuple[list, int]:
    priority = 0
    default_capability = 'view'
    streams_with_capability = []
    try:
        streams_as_str = []
        mapping_groups = filter_str.strip().split('|')
        for g in mapping_groups:
            str_and_stream = g.strip().split(':')
            if len(str_and_stream) > 2:
                raise ValueError('Using multiple ":" characters in one group of mapping')
            elif len(str_and_stream) == 1:
                streams_as_str = ast.literal_eval(str_and_stream[0])
                break
            else:
                if fnmatch.fnmatchcase(member_of, str_and_stream[0].strip("'").strip('"')):
                    streams_as_str = ast.literal_eval(str_and_stream[1])
                    break
            priority += 1
        for s in streams_as_str:
            split_str = s.split('/')
            if len(split_str) > 1:
                streams_with_capability.append((split_str[0], split_str[1],))
            else:
                streams_with_capability.append((split_str[0], default_capability,))
    except Exception as e:
        raise ValueError(f'Invalid string for mapping streams: {str(e)}')
    finally:
        return streams_with_capability, priority
