import React, { Component, Fragment } from "react";
import { Link } from "react-router-dom";
import PropTypes from "prop-types";
import { connect } from "react-redux";
import { setAlert } from "../../actions/alert";
import Alert from "../layout/Alert";

class Register extends Component {
    static propTypes = {
        setAlert: PropTypes.func.isRequired,
    };

    state = {
        name: "",
        email: "",
        password: "",
        conform_password: "",
    };

    onChangeHandler = (event) => {
        const name = event.target.name;
        const value = event.target.value;
        this.setState({ [name]: value });
    };

    onSubmitHandler = (event) => {
        event.preventDefault();
        if (this.state.password === this.state.conform_password) {
            console.log(this.state);
        } else {
            this.props.setAlert("Password And Conform Password Do Not Match !!!", "danger", 4000);
        }
    };

    render() {
        return (
            <Fragment>
                <section className="container">
                    <Alert />
                    <h1 className="large text-primary">Sign Up</h1>
                    <p className="lead">
                        <i className="fas fa-user"></i> Create Your Account
                    </p>
                    <form className="form" onSubmit={(e) => this.onSubmitHandler(e)}>
                        <div className="form-group">
                            <input
                                type="text"
                                placeholder="Name"
                                name="name"
                                value={this.state.name}
                                onChange={(e) => this.onChangeHandler(e)}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <input
                                type="email"
                                placeholder="Email Address"
                                name="email"
                                value={this.state.email}
                                onChange={(e) => this.onChangeHandler(e)}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <input
                                type="password"
                                placeholder="Password"
                                name="password"
                                minLength="8"
                                value={this.state.password}
                                onChange={(e) => this.onChangeHandler(e)}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <input
                                type="password"
                                placeholder="Confirm Password"
                                name="conform_password"
                                minLength="8"
                                value={this.state.conform_password}
                                onChange={(e) => this.onChangeHandler(e)}
                                required
                            />
                        </div>
                        <input type="submit" className="btn btn-primary" value="Register" />
                    </form>
                    <p className="my-1">
                        Already have an account? <Link to="login">Sign In</Link>
                    </p>
                </section>
            </Fragment>
        );
    }
}

export default connect(null, { setAlert })(Register);
