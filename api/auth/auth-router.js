// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const bcrypt = require('bcryptjs')

const User = require('../users/users-model')

const router = express.Router()

const { 
  checkPasswordLength, 
  checkUsernameExists, 
  checkUsernameFree 
} = require('./auth-middleware')

router.post('/register', checkPasswordLength, checkUsernameFree, async (req, res, next) => {
  const { username, password } = req.body
  const hPass = bcrypt.hashSync(password, 3)
  const [newUser] = await User.add({ username: username, password: hPass })
  res.status(201).json(newUser)
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.body
  if(bcrypt.compareSync(password, req.session.user.password)) {
    res.status(200).json({ message: `Welcome ${username}` })
  } else {
    res.status(401).json({ message: 'Invalid credentials' })
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.get('/logout', async (req, res, next) => {
  if(req.session.user) {
    const { username } = req.session.user
    req.session.destroy(err => {
      if(err) {
        res.status(200).json({ message: 'you wanted to leave, why are you still here?' })
      } else {
        res.status(200).json({ message: 'logged out' })
      }
    })
  } else {
    res.status(200).json({ message: 'no session' })
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router