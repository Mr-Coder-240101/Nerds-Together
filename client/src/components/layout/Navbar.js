import React, { Component, Fragment } from "react";
import { Link } from "react-router-dom";

class Navbar extends Component {
    render() {
        return (
            <Fragment>
                <nav className="navbar bg-dark">
                    <h1>
                        <Link to="">
                            <i className="fas fa-laptop-code"></i> Nerds Together
                        </Link>
                    </h1>
                    <ul>
                        <li>
                            <Link to="nerds">Nerds</Link>
                        </li>
                        <li>
                            <Link to="register">Register</Link>
                        </li>
                        <li>
                            <Link to="login">Login</Link>
                        </li>
                    </ul>
                </nav>
            </Fragment>
        );
    }
}

export default Navbar;
