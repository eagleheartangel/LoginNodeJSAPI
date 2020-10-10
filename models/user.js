'use strict';

const mongoose = require('mongoose');
// esquemas de mongoose y definir propiedades
const Schema = mongoose.Schema;

const UserSchema = Schema({
  name: String,
  surname: String,
  email: String,
  password: String,
  image: String,
  role: String,
});

module.exports = mongoose.model('User', UserSchema);
//lowercase y pluralizar el nombre
//users -> documentos (schema)
