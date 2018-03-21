var fs = require('fs');
var express = require('express');
var app = express();
var https = require('https');
var httputil = require('http');
var http = httputil.Server(app);
var bodyParser = require('body-parser');
var io = require('socket.io')(http);
var btoa = require('btoa');
var cookieParser = require('cookie-parser');
require('dotenv').config();

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

var unverified = {};
var verified = {};
var vlist;
var banlist;
var lastcheck = new Date();

const CLIENT_ID = process.env.CLIENT_ID; //these are provided by the discord app being used and obviously will not be public.
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const redirect = encodeURIComponent('http://localhost:55555/callback'); //the discord app must have this exact url or it won't allow this.

try{
	vlist = JSON.parse(fs.readFileSync('verifiedServers.json', 'utf8'));
} catch(e) {
	vlist = {};
	fs.writeFileSync('verifiedServers.json', JSON.stringify(vlist));
}

try{
	banlist = JSON.parse(fs.readFileSync('bans.json', 'utf8'));
} catch(e) {
	banlist = {ips: [], ids: []};
	fs.writeFileSync('bans.json', JSON.stringify(banlist));
}

//Catch and process server pings
app.post('/server', function (req, res) {
	var ip = req.connection.remoteAddress.split(',')[0];
	ip = ip.split(':').slice(-1)[0];
	if(banlist.ips.indexOf(ip) > -1){//no listing, no service.
		return;
	}
	if(req.body && req.body.port && req.body.title && req.body.playerlist && req.body.id){
		if(banlist.ids.indexOf(req.body.id) > -1){
			return;
		}
		var url = ip + ':' + req.body.port;
		//check if the server url is on our lists yet; if it is, update title, playerlist, and timestamp.
		if(vlist[url] && vlist[url].id == req.body.id){//existing verified
			verified[url] = {title: req.body.title, playerlist: req.body.playerlist, timestamp: new Date(), id: req.body.id};
		} else {//unverified
			unverified[url] = {title: req.body.title, playerlist: req.body.playerlist, timestamp: new Date(), id: req.body.id};
		}
	}
	res.send('POST request received!');
});

app.get('/', function(req, res){
	res.sendFile(__dirname + '/index.html');
});

app.get('/login', function(req, res){
	res.redirect('https://discordapp.com/oauth2/authorize?client_id='+CLIENT_ID+'&scope=identify&response_type=code&redirect_uri='+redirect);
});

app.get('/callback', function(req, res){
	var options = {
		host: 'discordapp.com',
		path: '/api/oauth2/token?client_id='+CLIENT_ID+'&client_secret='+CLIENT_SECRET+'&grant_type=authorization_code&code='+req.query.code+'&redirect_uri='+redirect,
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
	};

	var token = '';
	var request = https.request(options, function(response){
		response.setEncoding('utf8');
		response.on('data', function (chunk) {
			token += chunk;
		});

		response.on('end', function(){
			//put the token in a cookie and then send them back to the homepage.
			console.log(token);
			res.cookie('token', JSON.parse(token).access_token, {maxAge: 604800000});//discord tokens expire in 7 days.
			res.redirect('/');
		});
		response.on('error', function(err){
			res.redirect('/');
		});
	});

	request.on('error', function(e) {
		console.log('problem with request: ' + e.message);
	});
	request.write('');
	request.end();
});

io.on('connection', function(socket){
	//go through the list, verify what needs to be sent from the unverified and verified lists, and send it.
	//Only check for expired servers once a minute, regardless of traffic or how many reloads someone does.
	//The playerlists and names will remain as up to date as the server pings allow regardless of this check.
	var now = new Date();
	var discordid = 0;
	if((now - lastcheck)/60000 > 1){
		for (var url in unverified){
			// skip loop if the property is from prototype
			if (!unverified.hasOwnProperty(url)) continue;
			//check if more than five minutes have passed, if so remove it.
			if((now - unverified[url].timestamp)/60000 > 5){
				delete unverified[url];
			}
		}
		for (var url in verified){
			// skip loop if the property is from prototype
			if (!verified.hasOwnProperty(url)) continue;
			//check if more than five minutes have passed, if so remove it; the server file will preserve saved verifications.
			if((now - verified[url].timestamp)/60000 > 5){
				delete verified[url];
			}
		}
		lastcheck = now;
	}
	socket.emit("Serverlist", unverified, verified);
	socket.on('DiscordLogin', function(token, callback){
		var options = {
			host: 'discordapp.com',
			path: '/api/users/@me',
			method: 'GET',
			headers: {
				Authorization: 'Bearer '+token
			}
		};
		var data = '';
		var request = https.request(options, function(response){
			response.setEncoding('utf8');
			response.on('data', function (chunk) {
				data += chunk;
			});

			response.on('end', function(){
				var json = JSON.parse(data);
				if(json.id){
					discordid = json.id;
					callback(json.id);
					socket.on('verify', function(url, callback){
						//determine if the server's discord ID matches.
						//For the Discord version, we need to check that the server they're trying to verify matches their logged-in ID.
						if(unverified[url]){
							if(unverified[url].id == discordid){//verify the match from our own end.
								vlist[url] = {id: unverified[url].id};
								fs.writeFile('verifiedServers.json', JSON.stringify(vlist), function(err){
									if(err){console.log(err);} else {
										console.log(url+' is now verified under '+unverified[url].id);
										callback(url+' is now verified under '+unverified[url].id);
										verified[url] = {title: unverified[url].title, playerlist: unverified[url].playerlist, timestamp: new Date(), id: unverified[url].id};
										delete unverified[url];
										socket.emit("Serverlist", unverified, verified);
									}
								});
							} else {callback('Mismatched id.');}
						} else {callback('The server must be up to do this.');}
					});
				} else {
					callback(JSON.stringify({message: 'No id found in response.'}));
				}
			});
			response.on('error', function(err){
				console.log(err);
				callback(err);
			});
		});

		request.on('error', function(e) {
			console.log('problem with request: ' + e.message);
			callback(e);
		});
		request.end();
	});
	socket.on('login', function(username, password, callback){
		fs.readFile('logins.json', 'utf8', function(err, logins){
			if(err){callback(err);} else {
				logins = JSON.parse(logins);
				if(logins[username]){//valid username
					if(logins[username].password == password){//valid admin login
						//provide some sort of success callback.
						callback("Success!");
						//this occurs after success, it won't listen without an admin login.
						socket.on('verify', function(url, callback){
							if(unverified[url]){
								vlist[url] = {id: unverified[url].id};
								fs.writeFile('verifiedServers.json', JSON.stringify(vlist), function(err){
									if(err){console.log(err);} else {
										console.log(url+' is now verified under '+unverified[url].id);
										callback(url+' is now verified under '+unverified[url].id);
										verified[url] = {title: unverified[url].title, playerlist: unverified[url].playerlist, timestamp: new Date(), id: unverified[url].id};
										delete unverified[url];
										socket.emit("Serverlist", unverified, verified);
									}
								});
							} else {callback('The server must be up to do this.');}
						});
						socket.on('ban', function(id, isId){
							if(isId){
								if(id != 1){//don't do this for servers lacking proper IDs.
									banlist.ids.push(id);
								}
							} else {
								banlist.ips.push(id);
							}
							fs.writeFile('bans.json', JSON.stringify(banlist), function(err){
								if(err){console.log(err);} else {console.log(id+' has been added to the banlist.');}
							});
						});
					} else {//invalid login
						callback("Invalid login.");
					}
				} else {//invalid username
					callback("Invalid login.");
				}
			}
		});
	});
});

if(process.argv[2]){
	http.listen(process.argv[2], function(){
	  console.log('listening on *:'+process.argv[2]);
	});
} else {
	var prt = process.env.PORT || 0;
	http.listen(prt, function(){
	  console.log('listening on *:'+http.address().port);
	});
}
