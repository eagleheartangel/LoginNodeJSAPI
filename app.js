'use strict';
// Requires
const express = require('express');
const bodyParser = require('body-parser'); // datos a string
// Ejecutar express
const app = express();
// Cargar archivos de rutas
const user_routes = require('./routes/user');
// Middlewares
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
// Cors

//Reescribir rutas
app.use('/api', user_routes); //agregando api al url y llamando rutas
// Ruta de prueba

// Exportar el modulo
module.exports = app;
