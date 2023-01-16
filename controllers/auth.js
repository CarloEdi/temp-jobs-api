const User = require('../models/User')
const {StatusCodes} = require('http-status-codes')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const {BadRequestError, UnauthenticatedError} = require('../errors')

// Register
const register = async (req, res) => {
const user = await User.create({...req.body})
const token = jwt.sign({userId: user._id, name: user.name}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_LIFETIME})

res.status(StatusCodes.CREATED).json({user: {name: user.name}, token})
}

/////////////////////

// Login
const login = async (req, res) => {
    const {email, password} = req.body
    if(!email || !password) {
        throw new BadRequestError('Please provide email and password')
    }
    const user = await User.findOne({email: email})
    if(!user) {
        throw new UnauthenticatedError('Invalid Credentials')
    }
    // compare password
    const isPasswordCorrect = await user.comparePassword(password)
    if(!isPasswordCorrect) {
        throw new UnauthenticatedError('Invalid Password')
    }
    const token = jwt.sign({userId: user._id, name: user.name}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_LIFETIME})
    
    res.status(StatusCodes.OK).json({user: {name: user.name}, token})
}

module.exports = {register, login}