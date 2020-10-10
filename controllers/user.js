'use strict';
const validator = require('validator');
const bcrypt = require('bcrypt-nodejs');
const User = require('../models/user');
const jwt = require('../services/jwt');
const controller = {
  probando: function (peticion, respuesta) {
    return respuesta.status(200).send({
      mensaje: 'Soy el metodo probando',
    });
  },
  testeando: function (peticion, respuesta) {
    return respuesta.status(200).send({
      mensaje: 'Soy el metodo testeando',
    });
  },
  save: function (peticion, respuesta) {
    // Recoger los parametros de la peticion
    const params = peticion.body;
    // Validar los datos
    const validate_name = !validator.isEmpty(params.name);
    const validate_surname = !validator.isEmpty(params.surname);
    const validate_email =
      !validator.isEmpty(params.email) && validator.isEmail(params.email);
    const validate_password = !validator.isEmpty(params.password);

    // console.log(
    //   validate_email,
    //   validate_name,
    //   validate_surname,
    //   validate_password
    // );

    if (
      validate_name &&
      validate_surname &&
      validate_password &&
      validate_email
    ) {
      // Crear objeto de usuario
      const user = new User();

      // Asignar valores al objeto
      user.name = params.name;
      user.surname = params.surname;
      user.email = params.email.toLowerCase();
      user.role = 'ROLE_USER';
      user.image = null;
      // Comprobar si el usuario existe
      User.findOne({ email: user.email }, (err, issetUser) => {
        if (err) {
          return respuesta.status(500).send({
            message: 'Error al comprobar duplicidad de usuario',
          });
        }
        if (!issetUser) {
          // Si no existe

          // cifrar contraseña
          bcrypt.hash(params.password, null, null, (err, hash) => {
            user.password = hash;
            // Guardarlo usuarios
            user.save((err, userStored) => {
              if (err) {
                return respuesta.status(500).send({
                  message: 'Error al guardar el usuario',
                });
              }
              if (!userStored) {
                return respuesta.status(400).send({
                  message: 'El usuario no se ha guardado',
                });
              }
              // Devolver respuesta
              return respuesta
                .status(200)
                .send({ status: 'succes', user: userStored });
            }); // close save
          }); // close bcrypt
        } else {
          return respuesta.status(200).send({
            message: 'El usuario ya esta registrado',
          });
        }
      });
    } else {
      return respuesta.status(200).send({
        message: 'La validacion es incorrecta',
      });
    }
  },

  login: function (peticion, respuesta) {
    // Recoger los parametros de la peticion
    const params = peticion.body;

    // Validar datos
    const validate_email =
      !validator.isEmpty(params.email) && validator.isEmail(params.email);
    const validate_password = !validator.isEmpty(params.password);

    if (!validate_email || !validate_password) {
      return respuesta.status(200).send({
        message: 'Los datos son Incorrectos',
      });
    }
    // Buscar usuarios que coincidan con el email
    User.findOne({ email: params.email.toLowerCase() }, (err, user) => {
      if (err) {
        return respuesta.status(500).send({
          message: 'Error al intentar identificarse',
        });
      }
      if (!user) {
        return respuesta.status(404).send({
          message: 'El usuario no existe',
          user,
        });
      }
      // Si lo encuentra
      // Comprobar la contraseña (coincidencia de email y password / bcrypt)
      bcrypt.compare(params.password, user.password, (err, check) => {
        // Si es corresto
        if (check) {
          // Generar token de jwt y devolverlo ( mas tarde)
          if (params.gettoken) {
            // Devolver los datos
            return respuesta.status(200).send({
              token: jwt.createToken(user),
            });
          } else {
            // Limpiar objeto
            user.password = undefined;

            // Devolver los datos
            return respuesta.status(200).send({
              status: 'success',
              user,
            });
          }
        } else {
          return respuesta.status(200).send({
            message: 'Las credenciales no son correctas',
            user,
          });
        }
      });
    });
  },
};
module.exports = controller;
