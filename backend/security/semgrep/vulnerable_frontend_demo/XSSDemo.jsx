/*
 * XSSDemo.jsx
 *
 * NOT part of the DarkShield application. This is a small, intentionally
 * vulnerable React component used only to demonstrate the frontend_rules.yml
 * Semgrep pack (Phase 5) end-to-end during a live demo: point a /scan at
 * this file/folder and show that DarkShield finds these on its own.
 *
 * Do not import or render this component anywhere in a real app.
 */

import React, { useState } from "react";

// --- Vulnerability 1: dangerouslySetInnerHTML fed by unsanitized props ---
// Renders raw HTML directly from a comment string an attacker controls,
// bypassing React's built-in escaping. Caught by:
//   frontend-react-dangerously-set-innerhtml
function CommentDisplay(props) {
    return (
        <div className="comment" dangerouslySetInnerHTML={{ __html: props.userComment }} />
    );
}

// --- Vulnerability 2: insecure storage of an auth token ---
// Tokens in localStorage are readable by any script on the page (including
// injected XSS payloads); they should live in an httpOnly cookie instead.
// Caught by: frontend-insecure-storage-of-token
function login(username, password) {
    return fetch("/api/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
    })
        .then((res) => res.json())
        .then((data) => {
            localStorage.setItem("authToken", data.token);
            return data;
        });
}

export default function XSSDemo() {
    const [comment, setComment] = useState("");

    return (
        <div>
            <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Leave a comment (try <img src=x onerror=alert(1)>)"
            />
            <CommentDisplay userComment={comment} />
        </div>
    );
}

export { CommentDisplay, login };