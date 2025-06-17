// IMPORTS
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = express('jsonwebtoken');

const app = express();

// OPEN ROUTE - PUBLIC ROUTE
app.get('/', (req, res) => {
    res.status(200).json({msg: 'New API!'})
});

app.listen(3000)