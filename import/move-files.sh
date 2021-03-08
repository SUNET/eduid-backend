#!/bin/bash
#
# After import, move all the sources into a common src/eduid and adjust imports.
#

set -e
set -x

function move {
    src="${1}"
    dst="${2}"

    if [ -d "${src}" ]; then
	parent=$(dirname "${dst}")
	test -d "${parent}" || mkdir -p "${parent}"
	git mv "${src}" "${dst}"
    fi
}

git checkout import-old-repos
git branch -D move-imported-files-to-new-structure || true
git checkout -b move-imported-files-to-new-structure

move import/eduid-am/eduid_am				src/eduid/workers/am
move import/eduid-common/src/eduid_common/		src/eduid/common
move import/eduid-graphdb/src/eduid_graphdb/		src/eduid/graphdb
move import/eduid-lookup-mobile/eduid_lookup_mobile/	src/eduid/workers/lookup_mobile
move import/eduid_msg/eduid_msg/			src/eduid/workers/msg
move import/eduid-queue/src/eduid_queue/		src/eduid/queue
move import/eduid-scimapi/src/eduid_scimapi/		src/eduid/scimapi
move import/eduid-scimapi/src/eduid_satosa_plugins/	src/eduid/satosa
move import/eduid-userdb/src/eduid_userdb/		src/eduid/userdb
move import/eduid-webapp/src/eduid_webapp/		src/eduid/webapp

git commit -m "move imported files to new directory strucure"
