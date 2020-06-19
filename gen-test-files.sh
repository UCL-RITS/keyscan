#!/bin/bash

## This should regenerate the test files, using ssh-keygen, a lot.

# Just to make this all shorter.
function kg () {
  ssh-keygen -P "" "$@"
}

set -o errexit -o nounset

mkdir -p test-files
cd test-files

# Every type.
for kt in rsa ecdsa dsa ed25519; do
  kg -t "$kt" -C "$kt" -f "kt-$kt"
done
cat kt-*.pub >keytypes_test
command rm -v kt-*

# Creating an "example" situation.
kg -C "me@laptop" -f tmp-user_key_1
kg -C "me@desktop" -f tmp-user_key_2
kg -C "person@laptop" -f tmp-user_key_3
kg -C "person@my-desktop" -f tmp-user_key_4
kg -C "person@other-cluster" -f tmp-user_key_5

kg -C "we share this key" -f tmp-shared_key_1 
kg -C "we share this key also but it's allowed" -f tmp-shared_key_2

kg -C "I used this key on a public cluster unencrypted and now it's banned" -f tmp-banned_key_1

echo "# Some comment" >>authorized_keys_1
echo "# Some other comment" >>authorized_keys_2
echo "# These are forbidden" >>forbidden_keys
echo "# These are allowed even if forbidden" >>permitted_keys

echo "# Normal user keys" >>authorized_keys_1
echo "# Normal user keys" >>authorized_keys_2
cat tmp-user_key_{1,2}.pub >>authorized_keys_1
cat tmp-user_key_{3,4,5}.pub >>authorized_keys_2

echo "# Shared keys" >>authorized_keys_1
echo "# Shared keys" >>authorized_keys_2
cat tmp-shared_key_1.pub tmp-shared_key_2.pub >>authorized_keys_1
cat tmp-shared_key_1.pub tmp-shared_key_2.pub >>authorized_keys_2

echo "# Banned keys" >>authorized_keys_1
cat tmp-banned_key_1.pub >>authorized_keys_1
cat tmp-banned_key_1.pub >>forbidden_keys

cat tmp-shared_key_2.pub >>permitted_keys

command rm -v tmp-*

