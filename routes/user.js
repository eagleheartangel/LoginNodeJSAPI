'use strict';
const express = require('express');
const UserController = require('../controllers/user');

const router = express.Router();
const md_auth = require('../middlewares/authenticated');
// Rutas de prueba
router.get('/probando', UserController.probando);
router.post('/testeando', UserController.testeando);
// Rutas de usuarios
router.post('/register', UserController.save);
router.post('/login', UserController.login);
router.put('/update', md_auth.authenticated, UserController.update);

module.exports = router;
