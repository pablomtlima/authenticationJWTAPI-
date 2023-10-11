require('dotenv').config()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const express = require('express')
const { default: mongoose } = require('mongoose')
const cors = require('cors')

const app = express()

app.use(cors())
app.use(express.json())

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

const User = require('./models/Users')


app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa API' })
})


app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id

    try {
        
        const user = await User.findById(id, '-password')

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        return res.status(200).json({ user })

    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: 'Ocorreu um erro ao buscar o usuário' });
    }

})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']

    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado' })
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()

    } catch (error) {
        console.log(error)
        return res.status(400).json({ msg: 'Token inválido' })
    }
}

app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body

    // Validations
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória' })
    }
    if (password != confirmPassword) {
        return res.status(422).json({ msg: 'As senhas não conferem' })
    }

    // check if user exists
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: 'Este email já está sendo utilizado' })
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        user.save()

        res.status(201).json({ msg: 'Usuário criado com sucesso' })

    } catch (error) {
        console.log(error)
        res
            .status(500)
            .json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde' })
    }
})

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'O senha é obrigatória' })
    }

    
    const user = await User.findOne({ email: email })

    console.log(user._id)
    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado" })
    }

    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" })
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id
        }, secret)

        return res.status(200).json({ msg: 'Usuário autenticado com sucesso', token })

    } catch (error) {
        console.log(error)
        res.status(500).json(
            { msg: 'Aconteceu um erro no servidor, tente novamente mais tarde' })
    }


    return res.status(200).json({ msg: "ok" })
})

const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPass}@cluster0.bijk8uj.mongodb.net/?retryWrites=true&w=majority&appName=AtlasApp`)
    .then(() => {
        app.listen(3333)
        console.log('Conectou ao banco')
        console.log('Server is running 3333')
    })
    .catch((err) => console.log(err))
