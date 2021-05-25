import React, { Component, Fragment } from "react";
import { Link } from "react-router-dom";

class Landing extends Component {
    getRandomNumber = () => {
        return Math.floor(Math.random() * 5);
    };
    render() {
        return (
            <Fragment>
                <section className={`landing background${this.getRandomNumber()}`}>
                    <div className="dark-overlay">
                        <div className="landing-inner">
                            <h1 className="x-large">Nerds Together</h1>
                            <p className="lead">
                                Create A Nerd Profile, Share Questions And Get Help From Other Nerds
                            </p>
                            <div className="buttons">
                                <Link to="register" className="btn btn-primary">
                                    Sign Up
                                </Link>
                                <Link to="login" className="btn btn-light">
                                    Login
                                </Link>
                            </div>
                        </div>
                    </div>
                </section>
            </Fragment>
        );
    }
}

export default Landing;
