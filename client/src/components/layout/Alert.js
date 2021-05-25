import React, { Component, Fragment } from "react";
import PropTypes from "prop-types";
import { connect } from "react-redux";

class Alert extends Component {
    static propTypes = {
        alerts: PropTypes.array.isRequired,
    };

    getAlertComponent = () => {
        if (this.props.alerts === null || this.props.alerts.length === 0) {
            return <Fragment></Fragment>;
        } else {
            return (
                <Fragment>
                    {this.props.alerts.map((alert) => (
                        <div key={alert.id} className={`alert alert-${alert.alertType}`}>
                            {alert.message}
                        </div>
                    ))}
                </Fragment>
            );
        }
    };

    render() {
        return <Fragment>{this.getAlertComponent()}</Fragment>;
    }
}

const mapStateToProps = (state) => ({
    alerts: state.alerts,
});

export default connect(mapStateToProps)(Alert);
