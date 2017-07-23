First of all, I should thank you for your willing to contribute.

If you want to support a new MIME type:
1. Write new Signature.
2. Don't forget to link it with documation or existed MIME detection code from other project.
3. Write test for it. If you don't know how to run the test, read the `.travis.yml`.
4. Upgrade the version number in `lib/mime_sniff.lua`. If you add a new kind of Signature, increase minor number by one. Otherwise, increase patch number is just enough.
5. Squash to one commit and submit a pull request.

It's my duty to update the wiki after your pull request is merged.

If you want to fix a bug:
1. Write your bugfix.
2. Add a test to avoid regression.
3. Upgrade the patch part of the version number in `lib/mime_sniff.lua`.
4. Squash to one commit and submit a pull request.

If you want to fix a typo:
1. Fix it.
2. Squash to one commit and submit a pull request.
