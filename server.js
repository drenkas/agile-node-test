// Required Modules
const express    = require("express")
const morgan     = require("morgan")
const bodyParser = require("body-parser")
const jwt        = require("jsonwebtoken")
const mongoose   = require("mongoose")
const app        = express()
const request    = require("request")
const port       = process.env.PORT || 3001
const User       = require('./models/User')
const Token      = require('./models/Token')
const secret = "supersecret"

// Connect to DB
const uri = 'mongodb+srv://admin:admin@cluster0-r6p19.mongodb.net/subject-agile' 
mongoose.set('useFindAndModify', false)
mongoose.connect(uri, {useNewUrlParser: true }).then(
	() => {
		console.log('Connected to Mongo')
	},
	err => {
		console.log('\nerror connecting to Mongo: \n', err)
	}
  )

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(morgan("dev"))
app.use(function(req, res, next) {
	res.setHeader('Access-Control-Allow-Origin', '*')
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST')
	res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization')
	next()
})



app.post('/signin', function(req, res) {
	User.findOne({id: req.body.id, password: req.body.password}, function(err, user) {
		if (err) {
			res.json({
				type: false,
				data: "Error occured: " + err
			})
		} else {
			if (user) {
				const userOb = {
					id: user.id,
					typeId: user.type,
					password: user.password,
				}
				const tokenModel = new Token({
					id: user.id,
					token: jwt.sign(userOb, secret,{ expiresIn: 600 })
				})
				tokenModel.save(function(err, savedUser) {
					if (err) {
						return res.status(203).json(err)
					}
					res.json(savedUser.token)
				})
			} else {
				res.json({
					type: false,
					data: "Incorrect email/password"
				})    
			}
		}
	})
})

const idType = (id) => {
	const regPhone = /^(\s*)?(\+)?([- _():=+]?\d[- _():=+]?){10,14}(\s*)?$/i
	const regEmail = /^[-._a-z0-9]+@(?:[a-z0-9][-a-z0-9]+\.)+[a-z]{2,6}$/i
	if (regEmail.test(id))
		return ({
			type: 'mail',
			id: id
		})
	else if (regPhone.test(id))
	return ({
		type: 'phone',
		id: id
	})
	else return false
}

app.post('/signup', (req, res) => {
	const newId = idType(req.body.id)
	!newId ? res.json({type: false,
		data: "Wrong format"})
	: User.findOne({id: newId.id}, function(err, user) {
		if (err) {
			res.json({
				type: false,
				data: "Error occured: " + err
			})
		} else {
			if (user) {
				res.json({
					type: false,
					data: "User already exists!"
				})
			} else {
				const user = {
					id: newId.id,
					typeId: newId.type,
					password: req.body.password,
				}
				const tokenModel = new Token({
					id: newId.id,
					token: jwt.sign(user, secret,{ expiresIn: 600 })
				})
				const userModel = new User({
					id: newId.id,
					typeId: newId.type,
					password: req.body.password,
				})
				userModel.save(function(err) {
					if (err) {
						return res.status(203).json(err)
					}
					tokenModel.save(function(err, savedUser) {
						if (err) {
							return res.status(203).json(err)
						}
						res.json(savedUser.token)
					})
				})
			}
		}
	})
})

app.get('/info', ensureAuthorized, function(req, res) {
	Token.findOne({token: req.token}, function(err, user) {
		if (err) {
			res.json({
				type: false,
				data: "Error occured: " + err
			})
		} if (!user) {
			res.json({
				type: false,
				data: "Incorrect token!"
			})
		} else {
			continueLifeToken(req.token)
			jwt.verify(req.token, secret, function (err, verifiedJwt) {
				res.json({
					type: verifiedJwt.typeId,
					id: verifiedJwt.id
				})
			})
			
		}
	})
})

app.get('/latency', ensureAuthorized, function(req, res) {
	Token.findOne({token: req.token}, function(err, user) {
		if (err) {
			res.json({
				type: false,
				data: "Error occured: " + err
			})
		} if (!user) {
			res.json({
				type: false,
				data: "Incorrect token!"
			})
		} else {
			continueLifeToken(req.token)
			const timerStart = Date.now()
			request('http://www.google.com', function (error, response, body) {
				const timerEnd = Date.now()
				const result = timerEnd - timerStart
				res.json(result + "ms")
			})
		}
	})
})

app.get('/logout', ensureAuthorized, function(req, res) {
	Token.findOne({token: req.token}, function(err, user) {
		if (err) {
			res.json({
				type: false,
				data: "Error occured: " + err
			})
		} if (!user) {
			res.json({
				type: false,
				data: "Incorrect token!"
			})
		} else {
			if (req.query.all === "false") {
				Token.deleteOne({ token: req.token }, function (err) {
					if (err) res.json({
						type: false,
						data: "Error occured: " + err
					})
				})
			} else {
				Token.deleteMany({ id: user.id }, function (err) {
					if (err) res.json({
						type: false,
						data: "Error occured: " + err
					})
				})
			}
			res.json({type: true})
		}
	})
})

const continueLifeToken = (token) => {
	Token.updateOne({token: token}, { $set: { expireAt: new Date(Date.now() + 600000) }}, function(err, user) {
		if (err) {
			res.json({
				type: false,
				data: "Error occured: " + err
			})
		} else {
			jwt.verify(token, secret, function (err, verifiedJwt) {
				verifiedJwt.exp = Date.now() + 600
			})
			
		}
	})
}

function ensureAuthorized(req, res, next) {
	const bearerHeader = req.headers["authorization"]
	if (typeof bearerHeader !== 'undefined') {
		const bearer = bearerHeader.split(" ")
		const bearerToken = bearer[1]
		req.token = bearerToken
		next()
	} else {
		res.send(403)
	}
}


// Start Server
app.listen(port, function () {
	console.log( "Express server listening on port " + port)
})