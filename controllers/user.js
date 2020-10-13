'use strict';
const validator = require('validator');
const bcrypt = require('bcrypt-nodejs');
const fs = require('fs');
const path = require('path');
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
    try {
      var validate_name = !validator.isEmpty(params.name);
      var validate_surname = !validator.isEmpty(params.surname);
      var validate_email =
        !validator.isEmpty(params.email) && validator.isEmail(params.email);
      var validate_password = !validator.isEmpty(params.password);

      // console.log(
      //   validate_email,
      //   validate_name,
      //   validate_surname,
      //   validate_password
      // );
    } catch (err) {
      return respuesta.status(200).send({
        message: 'Faltan datos por enviar',
      });
    }

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
    try {
      var validate_email =
        !validator.isEmpty(params.email) && validator.isEmail(params.email);
      var validate_password = !validator.isEmpty(params.password);
    } catch (err) {
      return respuesta.status(200).send({
        message: 'Faltan datos por enviar',
      });
    }

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

  update: function (peticion, respuesta) {
    // Recoger datos del usuario
    const params = peticion.body;
    // Validar datos
    try {
      var validate_name = !validator.isEmpty(params.name);
      var validate_surname = !validator.isEmpty(params.surname);
      var validate_email =
        !validator.isEmpty(params.email) && validator.isEmail(params.email);
    } catch (err) {
      return respuesta.status(200).send({
        message: 'Faltan datos por enviar',
      });
    }
    // Eliminar propiedades inecesarias
    delete params.password;
    // Buscar y actualizar documento
    const userId = peticion.user.sub;

    // Comprobar si el email es unico
    if (peticion.user.email != params.email) {
      User.findOne({ email: params.email.toLowerCase() }, (err, user) => {
        if (err) {
          return respuesta.status(500).send({
            message: 'Error al intentar identificarse',
          });
        }
        if (user && user.email == params.email) {
          return respuesta.status(200).send({
            message: 'El email no puede ser modificado',
          });
        } else {
          User.findOneAndUpdate(
            { _id: userId },
            params,
            { new: true },
            (err, userUpdated) => {
              if (err) {
                return respuesta.status(500).send({
                  status: 'error',
                  message: 'Error al actualizar usuario',
                });
              }
              if (!userUpdated) {
                return respuesta.status(200).send({
                  status: 'error',
                  message: 'No se ha actualizado el usuario',
                });
              }
              // Devolver respuesta
              return respuesta.status(200).send({
                status: 'success',
                user: userUpdated,
              });
            }
          );
        }
      });
    } else {
      User.findOneAndUpdate(
        { _id: userId },
        params,
        { new: true },
        (err, userUpdated) => {
          if (err) {
            return respuesta.status(500).send({
              status: 'error',
              message: 'Error al actualizar usuario',
            });
          }
          if (!userUpdated) {
            return respuesta.status(200).send({
              status: 'error',
              message: 'No se ha actualizado el usuario',
            });
          }
          // Devolver respuesta
          return respuesta.status(200).send({
            status: 'success',
            user: userUpdated,
          });
        }
      );
    }
  },
  uploadAvatar: function (peticion, respuesta) {
    // Configurar el modulo multiparty (md) para habilitar subida de imagenes routes/users.js

    // Recoger el fichero de la peticion
    var file_name = 'Avatar no subido...';

    if (!peticion.files) {
      return respuesta.status(404).send({
        status: 'error',
        message: file_name,
      });
    }
    // Conseguir el nombre y la extension del archivo subido
    const file_path = peticion.files.file0.path;
    const file_split = file_path.split('/');
    // Advertencia ** en Windows seria file_path.split('\\');
    // Nombre del archivo
    var file_name = file_split[2];
    // Extension del archivo
    const ext_split = file_name.split('.');
    const file_ext = ext_split[1];

    // Comprobar extension (solo imagenes), si no es valida borrar fichero subido
    if (
      file_ext != 'png' &&
      file_ext != 'jpg' &&
      file_ext != 'jpeg' &&
      file_ext != 'gif'
    ) {
      fs.unlink(file_path, (err) => {
        return respuesta.status(200).send({
          status: 'error',
          message: 'La extension del archivo no es valida',
          file: file_ext,
        });
      });
    } else {
      // CSacar el id de usuario identificado
      const userId = peticion.user.sub;

      // Buscar y actualizar el documento de la BD
      User.findOneAndUpdate(
        { _id: userId },
        { image: file_name },
        { new: true },
        (err, userUpdated) => {
          if (err || !userUpdated) {
            return respuesta.status(500).send({
              status: 'error',
              message: 'Error al guardar el usuario',
            });
          }

          // Devolver respuesta
          return respuesta.status(200).send({
            status: 'success',
            user: userUpdated,
          });
        }
      );
    }
  },
  avatar: function (peticion, respuesta) {
    const fileName = peticion.params.fileName;
    const pathFile = './uploads/users/' + fileName;

    fs.exists(pathFile, (exists) => {
      if (exists) {
        return respuesta.sendFile(path.resolve(pathFile));
      } else {
        return respuesta.status(404).send({
          message: 'La imagen no existe',
        });
      }
    });
  },

  // Sacar usuarios de la base de datos o uno en concreto (por si usamos en el frontend)
  getUsers: function (peticion, respuesta) {
    User.find().exec((err, users) => {
      if (err || !users) {
        return respuesta.status(404).send({
          status: 'error',
          message: 'No hay usuarios que mostrar',
        });
      }
      return respuesta.status(200).send({
        status: 'success',
        users,
      });
    });
  },
  getUser: function (peticion, respuesta) {
    const userId = peticion.params.userId;
    User.findById(userId).exec((err, user) => {
      if (err || !user) {
        return respuesta.status(404).send({
          status: 'error',
          message: 'No existe el usuario',
        });
      }
      return respuesta.status(200).send({
        status: 'success',
        user,
      });
    });
  },
};
module.exports = controller;
