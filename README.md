This is a node.js made for a college project. The server will get a video sent by the user via an html form, and a token. The server will then verify the validity of the token, if the token is not valid it will tell the user to login. If the token was valid, it would then take the video and compress the video and rename the video to match the user's username. It would then upload the video to an AWS s3 bucket for storage.
