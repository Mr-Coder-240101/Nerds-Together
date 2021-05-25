import React, { Component, Fragment } from "react";
import { Link } from "react-router-dom";

class Login extends Component {
    state = {
        email: "",
        password: "",
    };

    onChangeHandler = (event) => {
        const name = event.target.name;
        const value = event.target.value;
        this.setState({ [name]: value });
    };

    onSubmitHandler = (event) => {
        event.preventDefault();
        console.log(this.state);
    };

    render() {
        return (
            <Fragment>
                <section className="container">
                    <h1 className="large text-primary">Sign In</h1>
                    <p className="lead">
                        <i className="fas fa-user"></i> Sign into Your Account
                    </p>
                    <form className="form" onSubmit={(e) => this.onSubmitHandler(e)}>
                        <div className="form-group">
                            <input
                                type="email"
                                placeholder="Email Address"
                                name="email"
                                value={this.state.name}
                                onChange={(e) => this.onChangeHandler(e)}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <input
                                type="password"
                                placeholder="Password"
                                name="password"
                                value={this.state.name}
                                onChange={(e) => this.onChangeHandler(e)}
                                required
                            />
                        </div>
                        <input type="submit" className="btn btn-primary" value="Login" />
                    </form>
                    <p className="my-1">
                        Don't have an account? <Link to="register">Sign Up</Link>
                    </p>
                </section>
            </Fragment>
        );
    }
}

export default Login;
