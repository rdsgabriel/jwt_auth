const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const app = express();
const port = 3000;

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

app.use(express.json());

// rota pública
app.get('/', (req, res) => {
  res.send('Hello World');
});

const checkToken = (req, res, next) => {
  // eslint-disable-next-line dot-notation
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ msg: 'Acesso negado' });
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ msg: ' Token inválido ' });
  }
};
// rota privada
app.get('/user/:id', checkToken, async (req, res) => {
  const { id } = req.params;

  const user = await User.findById(id, '-password');

  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado!' });
  }

  res.status(202).json({ msg: 'Usuário encontrado', user });
});

// register
app.post('/auth/register', async (req, res) => {
  const {
    name, email, password, confirmpassword,
  } = req.body;

  if (!name) {
    return res.status(422).json({ msg: 'O nome é obrigatório!' });
  }

  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' });
  }

  if (!password) {
    return res.status(422).json({ msg: 'A senha é obrigatória!' });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: 'As senhas devem ser iguais!' });
  }

  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(422).json({ msg: 'Email já cadastrado' });
  }

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: 'Usuário criado com sucesso.' });
  } catch (error) {
    res.status(500).json({ msg: 'error' });
  }
});
// login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' });
  }

  if (!password) {
    return res.status(422).json({ msg: 'A senha é obrigatória!' });
  }

  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(422).json({ msg: 'Email não cadastrado!' });
  }

  const checkPass = await bcrypt.compare(password, user.password);

  if (!checkPass) {
    return res.status(404).json({ msg: 'Senha incorreta!' });
  }

  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret,
    );

    res.status(200).json({ msg: 'autenticação realizada com sucesso.', token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: 'Ocorreu um erro, tente novamente mais tarde.' });
  }
});

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.u71lzom.mongodb.net/`)
  .then(() => {
    app.listen(port, () => console.log(`> [server] Running at http://localhost:${port}`));
  })
  .catch((err) => console.log(err));
