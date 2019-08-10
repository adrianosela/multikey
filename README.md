# multikey - secrets framework

Example use cases:

- I want anyone on my team to be able to decrypt shared secrets with their own key locally
- I want my team to be able to access a highly privileged secret in emergency situations, by having n/N team members provide their key
- I want my deployment to decrypt its runtime secrets, by fetching its decryption key from AWS KMS

... many more