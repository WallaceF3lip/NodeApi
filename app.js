// IMPORTS
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// CONFIG JSON RESPONSE
app.use(express.json())

const User = require('./models/User');

// OPEN ROUTE - PUBLIC ROUTE
app.get('/', (req, res) => {
    res.status(200).json({msg: 'New API!'})
});

// PRIVATE ROUTE 
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id;

    // CHECK IF USER EXISTS
    const user = await User.findById(id, "-password");

    if(!user){
        return res.status(404).json({msg: 'Usuário nao encontrado!'})
    }

    res.status(200).json({user});
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(!token){
        return res.status(401).json({msg: 'Acesso negado!'})
    }

    try {
        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();
        
    } catch (error) {
        return res.status(400).json({msg: 'Token inválido!'});        
    }
}

// REGISER USER
app.post('/auth/register', async (req, res) => {
    
    const { name, email, password, confirmPassword } = req.body;

    // VALIDATIONS
    if(!name){
        console.log("Name: ", name);
        
        return res.status(422).json({msg: 'O nome é obrigatório!'})
    }

    if(!email){
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }

    if(!password){
        return res.status(422).json({msg: 'A senha é obrigatório!'})
    }
    
    if(password !== confirmPassword){
        return res.status(422).json({msg: 'A senha não confere!'})
    }

    // CHECK IF USER EXISTS
    const userExists = await User.findOne({email: email});

    if(userExists){
        return res.status(422).json({msg: 'Por favor, utilize outro email!'})
    }

    // CREATE PASSWORD
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // CREATE USER
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {

        await user.save();
        res.status(201).json({msg: 'Usuário criado com sucesso!'});
        
    } catch (error) {
        console.log("error: ",error);  
        res.status(500).json({msg: 'Erro no servidor! Tente novamente mais tarde!'});
    }
});

// LOGIN USER
app.post('/auth/login', async (req, res) => {

    const { email, password } = req.body;

    // VALIDATIONS
    if(!email){
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }

    if(!password){
        return res.status(422).json({msg: 'A senha é obrigatório!'})
    }

    // CHECK IF USER EXISTS
    const user = await User.findOne({email: email});

    if(!user){
        return res.status(404).json({msg: 'Usuario não encontrado!'})
    }

    // CHECK IF PASSWORD MATCH
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword){
        return res.status(422).json({msg: 'Senha inválida!'})
    }

    try {

        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
                id: user._id
            }, 
            secret,
        )

        res.status(200).json({msg: 'Autenticado com sucesso!', token});
        
    } catch (error) {
        console.log("error: ",error);  
        res.status(500).json({msg: 'Erro no servidor! Tente novamente mais tarde!'});
    }
})

// CREDENCIAS
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@nodeapi.1ylbuk2.mongodb.net/?retryWrites=true&w=majority&appName=NodeAPI`
    )
    .then(() => {
        app.listen(3000)
        console.log('Connected to DB')
    })
    .catch((err) => console.log(err));