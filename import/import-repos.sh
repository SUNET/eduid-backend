#!/bin/bash
#
# This script was used to import all the eduID backend repositories into this new common repository.
#
# A lot of this came from https://stackoverflow.com/questions/13040958/merge-two-git-repositories-without-breaking-file-history
#

set -e
set -x

SUBMODULES="eduid-am eduid-common eduid-graphdb eduid-lookup-mobile eduid_msg eduid-userdb eduid-queue eduid-scimapi eduid-webapp"

for mod in ${SUBMODULES}; do

    # Add a remote for and fetch the old repo
    # (the '--fetch' (or '-f') option will make git immediately fetch commits to the local repo after adding the remote)
    git remote rm "old_${mod}" || true
    git remote add --fetch "old_${mod}" https://github.com/SUNET/${mod}.git

    # Merge the files from old_a/master into new/master
    git merge "old_${mod}"/master --allow-unrelated-histories || \
	git merge "old_${mod}"/main --allow-unrelated-histories

    # Move the old_a repo files and folders into a subdirectory so they don't collide with the other repo coming later
    rm -rf "import/${mod}"
    mkdir "import/${mod}"
    git mv -k * .??* "import/${mod}"

    # Commit the move
    git commit -m "Move ${mod} files into subdir while merging repositories"
done
