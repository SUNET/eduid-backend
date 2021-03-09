#!/bin/bash

set -e

function replace {
    where="${1}"
    old="${2}"
    new="${3}"

    find "${where}" -type f -name '*.py' -print0 | xargs -0 grep --files-with-matches "${old}" | while read -r f; do
	sed -i -e "s#${old}#${new}#g" "${f}"
    done
}

git checkout src

git checkout move-imported-files-to-new-structure
git branch -D update-imports || true
git checkout -b update-imports


replace src/ " eduid_am"		" eduid.workers.am"
replace src/ " eduid_common"		" eduid.common"
replace src/ " eduid_graphdb"		" eduid.graphdb"
replace src/ " eduid_lookup_mobile"	" eduid.workers.lookup_mobile"
replace src/ " eduid_msg"		" eduid.workers.msg"
replace src/ " eduid_queue"		" eduid.queue"
replace src/ " eduid_scimapi"		" eduid.scimapi"
replace src/ " eduid_satosa_plugins"	" eduid.satosa"
replace src/ " eduid_userdb"		" eduid.userdb"
replace src/ " eduid_webapp"		" eduid.webapp"

replace src/ "(eduid_am"		"(eduid.workers.am"
replace src/ "(eduid_common"		"(eduid.common"
replace src/ "(eduid_graphdb"		"(eduid.graphdb"
replace src/ "(eduid_lookup_mobile"	"(eduid.workers.lookup_mobile"
replace src/ "(eduid_msg"		"(eduid.workers.msg"
replace src/ "(eduid_queue"		"(eduid.queue"
replace src/ "(eduid_scimapi"		"(eduid.scimapi"
replace src/ "(eduid_satosa_plugins"	"(eduid.satosa"
replace src/ "(eduid_userdb"		"(eduid.userdb"
replace src/ "(eduid_webapp"		"(eduid.webapp"

replace src/ "^eduid_common"		"eduid.common"
replace src/ "eduid_common.api."	"eduid.common.api."
replace src/ "eduid_common.authn."	"eduid.common.authn."
replace src/ "eduid_common.config."	"eduid.common.config."

replace src/ "eduid_webapp.actions."	"eduid.webapp.actions."
replace src/ "patch('eduid_webapp."	"patch('eduid.webapp."
replace src/ "patch('eduid_userdb."	"patch('eduid.userdb."

replace src/ "eduid_am.tasks"		"eduid.workers.am.tasks"

replace src/eduid/common/api/translation.py "eduid_webapp" "eduid.webapp"


# special cases
sed -i -e "s#self.eduid.userdb#self.eduid_userdb#g" src/eduid/satosa/scimapi/scim_attributes.py

replace src/eduid/workers/ "class eduid.workers." "class eduid_"

git commit -m "update imports after moving imported files" src/
