'use strict';

const mongoose = require('mongoose');
const express = require('express');

//importar config de app.js
const app = require('./app');
const port = process.env.PORT || 3000;
// Conexion a base de datos
mongoose.Promise = global.Promise;
mongoose
  .connect(
    'mongodb+srv://eagleangel:Maam15908400@cluster0.0x11k.mongodb.net/eagleangel1?retryWrites=true&w=majority',
    { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false }
  )
  .then(() => {
    console.log('Coneccion realizada');
    // Servidor
    app.listen(port, () => {
      console.log('Servidor corriendo perfectamente en puerto', port);
    });
  })
  .catch((error) => console.log('error'));
