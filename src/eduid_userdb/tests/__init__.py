#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the SUNET nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import unittest
from typing import Any, Dict, List, Tuple


class DictTestCase(unittest.TestCase):
    """
    """
    maxDiff = None

    @classmethod
    def normalize_data(cls, expected: List[Dict[str, Any]], obtained: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Remove timestamps that in general are created at different times
        and compare the resulting dicts
        """
        for elist in (expected, obtained):
            for elem in elist:
                cls.normalize_elem(elem)

        return expected, obtained

    @classmethod
    def normalize_elem(cls, elem: Dict[str, Any]) -> Dict[str, Any]:
        if 'created_ts' in elem:
            del elem['created_ts']
        if 'modified_ts' in elem:
            del elem['modified_ts']

        if 'application' in elem:
            elem['created_by'] = elem.pop('application')

        if 'source' in elem:
            elem['created_by'] = elem.pop('source')

        if 'credential_id' in elem:
            elem['id'] = elem.pop('credential_id')

        for key in elem:
            if isinstance(elem[key], dict):
                cls.normalize_elem(elem[key])

        for key in ('created_by', 'application', 'verified_ts', 'verified_by'):
            if key in elem and elem[key] is None:
                del elem[key]
