const express = require('express');
const cors = require('cors');
const argon2 = require('@node-rs/argon2');
const jwt = require('jsonwebtoken');
const con = require('./db_config');

const app = express();
app.use(cors());
app.use(express.json());

// FIXME: move it to safer place
const JWT_KEY = 'sdf1216werxfw@dsjfrewi';

// hash the password
app.get('/api/password/:raw', (req, res) => {
    const hash = argon2.hashSync(req.params.raw);
    // console.log(hash.length);  //97?
    res.send(hash);
});
