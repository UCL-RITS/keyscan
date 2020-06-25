# keyscan

`keyscan` is intended to find duplicated or banned `authorized_keys` entries (i.e. public keys) on a shared cluster.

## Usage

The command-line tool takes a config file in YAML format (default: `/etc/keyscan/config.yaml`).

A template with defaults commented out is in `etc/config.yaml`.

Running just `keyscan`, without a config file, will use the default settings, which are suitable for a basic sweep.

**Warning:** expanding the globs to read in all the key files on a filesystem with slow metadata ops can take some time.


## Example

A script to quickly generate some demonstration files is included, at `gen-test-files.sh`.

You can run that, and then scan the results:

```
# Clone the repo and build the executable
git clone https://github.com/UCL-RITS/keyscan.git
cd keyscan
go build .

# Generate the test data in test-files/
./gen-test-files.sh

# Then scan using the config for the test data from etc/

$ keyscan --config etc/test-config.yaml
[...Output...]
```

It comes out as a pile of JSON, so for a quick look, just passing it through `jq` can be helpful:

```
$ keyscan --config etc/test-config.yaml | jq
{
  "ForbiddenKeys": [
    {
      "ProblemType": 1,
      "ProblemKey": {
        "Owner": "uccaiki",
        "OwnerID": 501,
        "Key": {
          "N": 1.7976931348623157e+308,
          "E": 65537
        },
        "SourceFile": "/Users/uccaiki/Code/keyscan/test-files/authorized_keys_1",
        "SourceLine": 7,
        "Comment": "we share this key also but it's allowed"
      },
      "RelatedKeys": [
        {
          "Owner": "uccaiki",
          "OwnerID": 501,
          "Key": {
            "N": 1.7976931348623157e+308,
            "E": 65537
          },
          "SourceFile": "./test-files/permitted_keys",
          "SourceLine": 2,
          "Comment": "we share this key also but it's allowed"
        }
      ]
    },
[...etc...]
```

