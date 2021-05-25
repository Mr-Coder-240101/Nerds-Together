// Module
import React, { Fragment } from "react";
import { BrowserRouter as Router, Route, Switch } from "react-router-dom";
import { Provider } from "react-redux";
// CSS
import "./App.css";
// Components
import Login from "./components/authentication/Login";
import Register from "./components/authentication/Register";
import Landing from "./components/layout/Landing";
import Navbar from "./components/layout/Navbar";
// Store
import store from "./store";

const App = () => {
    return (
        <Fragment>
            <Provider store={store}>
                <Router>
                    <Navbar />
                    <Route exact path="/" component={Landing} />
                    <Switch>
                        <Route exact path="/login" component={Login} />
                        <Route exact path="/register" component={Register} />
                    </Switch>
                </Router>
            </Provider>
        </Fragment>
    );
};

export default App;
