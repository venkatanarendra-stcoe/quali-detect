import { Component } from "react";
import { ErrorState } from "./error-state.jsx";

/** Catches render errors of a subtree and shows the error state instead of a blank screen. */
export class ErrorBoundary extends Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error) {
    // Details stay in the console for developers; the UI shows a generic message only.
    console.error("Unhandled render error", error);
  }

  render() {
    if (this.state.error) {
      return (
        <ErrorState
          fullPage={this.props.fullPage}
          error={this.state.error}
          onRetry={() => this.setState({ error: null })}
        />
      );
    }
    return this.props.children;
  }
}
