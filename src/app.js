import express, { request, response } from "express";
import users from "./database";
import { v4 as uuidv4 } from "uuid";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
app.use(express.json());

// Middleware
const ensureAuthorizationMiddleware = (request, response, next) => {
  let authorization = request.headers.authorization;

  if (!authorization) {
    return response.status(401).json({
      message: "Missing authorization headers",
    });
  }

  authorization = authorization.split(" ")[1];

  return jwt.verify(authorization, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return response.status(401).json({
        message: "Missing authorization headers",
      });
    }

    request.user = {
      id: decoded.sub,
    };

    return next();
  });
};

const ensureUserExistMiddleware = (request, response, next) => {
  const userIndex = users.findIndex(
    (element) => element.uuid === `${request.user.id}`
  );

  if (userIndex === -1) {
    return response.status(404).json({
      message: "User not found",
    });
  }

  request.user = {
    userIndex: userIndex,
  };

  next();
};

const ensureAdminMiddleware = (request, response, next) => {
  const user = users[request.user.userIndex];

  if (!user.isAdm) {
    return response.status(403).json({
      message: "Missing admin permissions",
    });
  }

  return next();
};

// Service
const createUserService = async (userData) => {
  const userExist = users.find((element) => element.email === userData.email);

  if (userExist) {
    return [409, { message: "E-mail already registred" }];
  }

  const user = {
    uuid: uuidv4(),
    ...userData,
    password: await hash(userData.password, 10),
    createdOn: new Date(),
    updatedOn: new Date(),
  };

  users.push(user);

  const { uuid, name, email, password, isAdm, createdOn, updatedOn } = user;
  const userReturn = { uuid, name, email, isAdm, createdOn, updatedOn };

  return [201, userReturn];
};

const createSessionService = async ({ email, password }) => {
  const user = users.find((element) => element.email === email);

  if (!user) {
    return [401, { message: "Wrong email or password" }];
  }

  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return [401, { message: "Wrong email or password" }];
  }

  const token = jwt.sign({}, "SECRET_KEY", {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [200, { token }];
};

const listUsersService = () => {
  return [200, users];
};

const retrieveUserService = (request) => {
  let authorization = request.headers.authorization;

  authorization = authorization.split(" ")[1];

  return jwt.verify(authorization, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return response.status(401).json({
        message: "Missing authorization headers",
      });
    }
    let user = users.find((element) => element.uuid === `${decoded.sub}`);
    const { uuid, name, email, password, isAdm, createdOn, updatedOn } = user;
    user = { uuid, name, email, isAdm, createdOn, updatedOn };

    return [200, user];
  });
};

const updateUserService = async (request) => {
  const id = request.originalUrl.slice(7);
  const update = request.body;
  const user = users[request.user.userIndex];

  if (id.length < 1 || user.uuid !== id) {
    return [404, { message: "User not found" }];
  }

  for (const propertyUpdate in update) {
    for (const propertyUser in user) {
      if (propertyUpdate === "isAdm" && user[propertyUser] === false) {
        return [403, { message: "Missing admin permissions" }];
      }

      if (propertyUpdate === "password") {
        user[propertyUser] = await hash(update[propertyUpdate], 10);
      }

      if (propertyUpdate === propertyUser) {
        user[propertyUser] = update[propertyUpdate];
      }
    }
  }

  user.updatedOn = new Date();
  const { uuid, name, email, password, isAdm, createdOn, updateOn } = user;

  return [200, { uuid, name, email, isAdm, createdOn, updateOn }];
};

const deleteUserService = (request) => {
  const {
    originalUrl,
    user: { id: userId },
  } = request;

  const originalUrlId = originalUrl.slice(7);
  const index = users.findIndex((element) => element.uuid === userId);

  if (userId !== originalUrlId) {
    if (!users[index].isAdm) {
      return [403, { message: "Missing admin permissions" }];
    }

    const indexUserRemove = users.findIndex(
      (element) => element.uuid === originalUrlId
    );
    users.slice(indexUserRemove, 1);
    return [204, {}];
  }

  users.slice(index, 1);
  return [204, {}];
};

// Controller
const createUserController = async (request, response) => {
  const [status, data] = await createUserService(request.body);
  return response.status(status).json(data);
};

const createSessionController = async (request, response) => {
  const [status, data] = await createSessionService(request.body);
  return response.status(status).json(data);
};

const listUsersController = (request, response) => {
  const [status, data] = listUsersService();
  return response.status(status).json(data);
};

const retrieveUserController = (request, response) => {
  const [status, data] = retrieveUserService(request);
  return response.status(status).json(data);
};

const updateUserController = async (request, response) => {
  const [status, data] = await updateUserService(request);
  return response.status(status).json(data);
};

const deleteUserController = (request, response) => {
  const [status, data] = deleteUserService(request);
  return response.status(status).json(data);
};

app.post("/users", createUserController);
app.post("/login", createSessionController);
app.get(
  "/users",
  ensureAuthorizationMiddleware,
  ensureUserExistMiddleware,
  ensureAdminMiddleware,
  listUsersController
);

app.get(
  "/users/profile",
  ensureAuthorizationMiddleware,
  ensureUserExistMiddleware,
  retrieveUserController
);
app.patch(
  "/users/:id",
  ensureAuthorizationMiddleware,
  ensureUserExistMiddleware,
  updateUserController
);
app.delete("/users/:id", ensureAuthorizationMiddleware, deleteUserController);

app.listen(3000, () => {
  console.log("Server running in port 3000");
});

export default app;
