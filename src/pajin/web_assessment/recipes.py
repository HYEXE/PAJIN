"""Target-specific recipes; the browser and diagnostic engines stay target-neutral."""

from pajin.web_assessment.models import (
    DOMXSSRecipe,
    LoginRecipe,
    ObjectAccessRecipe,
    RegistrationRecipe,
    SQLLoginRecipe,
    WebAssessmentPlan,
)


def juice_shop_plan(origin: str) -> WebAssessmentPlan:
    return WebAssessmentPlan(
        name="juice-shop-web-assessment",
        origin=origin,
        login=LoginRecipe(
            route="/#/login",
            username_selector="#email",
            password_selector="#password",
            submit_selector="#loginButton",
            activation_mode="password-enter",
            success_selector="#navbarLogoutButton",
            success_activation_selector="button[aria-label='Show/hide account menu']",
            success_activation_mode="enter",
            endpoint="/rest/user/login",
            dismiss_selectors=("button[aria-label='Close Welcome Banner']", ".cc-dismiss"),
        ),
        registration=RegistrationRecipe(endpoint="/api/Users/"),
        routes=("/#/search", "/#/contact", "/#/about"),
        route_ready_selectors={
            "/#/search": "app-search-result",
            "/#/contact": "app-contact",
            "/#/about": "app-about",
        },
        navigation_selectors=("button[aria-label='Open Sidenav']",),
        allowed_post_paths=("/rest/user/login", "/api/Users/"),
        deny_paths=(
            "/rest/user/reset-password",
            "/rest/user/change-password",
            "/socket.io/",
        ),
        sql_login=SQLLoginRecipe(impact_endpoint="/api/Users/"),
        object_access=ObjectAccessRecipe(endpoint_template="/rest/basket/{id}"),
        dom_xss=DOMXSSRecipe(
            route_template="/#/search?q={payload}",
            ready_selector="app-search-result",
        ),
    )
