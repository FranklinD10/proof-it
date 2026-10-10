import * as basket from "./basket";
import * as security from "./insecurity";
app.get("/rest/basket/:id", security.isAuthorized(), basket.retrieveBasket());
