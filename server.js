/* 
    Node js server
    Dogmented Reality
    2022 
*/
// TODO: standardize capitalization of parameters in info.json

var https = require("https");
var http = require("http");
var fs = require("fs");
var formidable = require("formidable");
var jwt = require("jsonwebtoken"); // library for decoding and verifying tokens
var jwktoPem = require("jwk-to-pem");
const AWS = require("aws-sdk"); //aws library
const jwt_decode = require("jwt-decode");
var ffmpegPath = require("@ffmpeg-installer/ffmpeg").path;
var ffmpeg = require("fluent-ffmpeg");
ffmpeg.setFfmpegPath(ffmpegPath);

var info = JSON.parse(fs.readFileSync("info.json"));
var server;
// aws authetication info
const ID = info.ID;
const SECRET = info.SECRET;
const BUCKET_NAME = info.BUCKET_NAME;

const s3 = new AWS.S3({
	accessKeyId: ID,
	secretAccessKey: SECRET,
});

console.log("S3 initialized..");

//convert public key to pems
var jwk = JSON.parse(fs.readFileSync("jwks.json"));
var pem0 = jwktoPem(jwk.keys[0]);
var pem1 = jwktoPem(jwk.keys[1]);

console.log("JWKS parsed..");

//server code
var ser = function (req, res) {
	if (req.method == "POST") {
		console.log("POST began..");
		var form = new formidable.IncomingForm(); // raw incoming post info

		var decodedT; // payload of decoded token

		var validToken = true; // boolean if token is valid

		console.log("Parsing form..");
		form.parse(req, function (err, fields, files) {
			// parses post info
			console.log("Verifying token..");

			var token = fields.accessToken; // gets token
			var decodedHeader = jwt_decode(token, { header: true }); //decodes header of token

			if (decodedHeader.kid == jwk.keys[0].kid) {
				// checks if kid in token matches first jwk kid
				//checks token signature, algorithm, and issuer
				jwt.verify(token, pem0, { algorithms: [info.alg], issuer: info.iss }, function (err, decodedToken) {
					if (err) {
						// if signature, algorithm, or issuer is not correct
						console.log("Signature, algorithm or issuer were incorrect. (kid 1)");
						res.write("Make sure you are logged in");
						res.end();
						validToken = false;
					} else if (decodedToken.token_use != "access") {
						// checks if token is access token
						console.log("Not an access token. (kid 1)");
						res.write("Make sure you are logged in");
						res.end();
						validToken = false;
					} else if (decodedToken.client_id != info.client) {
						// check client id
						console.log("Incorrect client ID. (kid 1)");
						res.write("Make sure you are logged in");
						res.end();
						validToken = false;
					}
					decodedT = decodedToken; // saves token of decoded token
				});
			} else if (decodedHeader.kid == jwk.keys[1].kid) {
				// checks if kid in token matches second jwk kid
				// checks token signature, algorithm, and issuer
				jwt.verify(token, pem1, { algorithms: [info.alg], issuer: info.iss }, function (err, decodedToken) {
					if (err) {
						// if signature, algorithm, or issuer is not correct
						console.log("Signature, algorithm or issuer were incorrect. (kid 2)");
						res.write("Make sure you are logged in");
						res.end();
						validToken = false;
					} else if (decodedToken.token_use != "access") {
						// checks token is access token
						console.log("Not an access token. (kid 2)");
						res.write("Make sure you are logged in");
						res.end();
						validToken = false;
					} else if (decodedToken.client_id != info.client) {
						// checks client id
						console.log("Incorrect client ID. (kid 2)");
						res.write("Make sure you are logged in");
						res.end();
						validToken = false;
					}
					decodedT = decodedToken; // saves payload of decoded token
				});
			}
			if (validToken) {
				// checks token was valid
				var username = decodedT.username;
				console.log("Verified user: " + username);

				console.log("Saving file (480x)..");
				var path = files.filetoupload.filepath; //temporary path to video

				// indentation for end function
				ffmpeg(path)
					.size("480x?")
					.save(info.Path + username + ".mp4")
					.on("error", function (err, stdout, stderr) {
						console.log("Cannot process video: " + err.message);
						res.write("Make sure you record a video");
						res.end();
					})
					.on("end", function () {
						var filecontent = fs.readFileSync(info.Path + username + ".mp4"); // content of video
						var params = {
							// s3 upload info
							Bucket: BUCKET_NAME,
							Key: username + ".mp4",
							Body: filecontent,
						};

						console.log("Uploading to S3..");
						s3.upload(params, function (err, data) {
							//upload to s3
							if (err) {
								console.log("Upload failed");
								res.write("Could not upload video try again later");
								res.end();
							} else {
								fs.unlinkSync(info.Path + username + ".mp4");

								// if we're here the upload was successful
								console.log("Upload successful.");
								res
									.writeHead(301, {
										Location: "https://dogmented.dev/upload-success.html",
									})
									.end(); // redirects user to home page
							}
						});
					});
			} else {
				// if not valid do nothing
				console.log("Invalid token received..");
				return;
			}
		});
	}
};

// TODO: use boolean value instead of string
if (info.https === "true") {
	console.log("Using HTTPS");
	var options = {
		key: fs.readFileSync(info.pkey, "utf8"),
		cert: fs.readFileSync(info.cer, "utf8"),
		ca: fs.readFileSync(info.chain, "utf8"),
	};

	var server = https.createServer(options, ser);
} else {
	console.log("Using plain HTTP");
	var server = http.createServer(ser);
}

const port = 3000;
const host = "0.0.0.0";
server.listen(port, host);
console.log(`Listening at http(s)://${host}:${port}`);
