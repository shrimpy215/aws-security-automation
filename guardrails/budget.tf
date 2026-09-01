resource "aws_budgets_budget" "account_monthly" {
  name         = "account-monthly-cost"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # --- Early warning: half the budget consumed -----------------------------
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  # --- Budget actually exceeded --------------------------------------------
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  # --- The important one ---------------------------------------------------
  # FORECASTED fires when AWS PROJECTS you will exceed the budget by month
  # end, based on current burn rate. This is what catches a stack you forgot
  # to destroy — days before the money is actually spent, rather than after.
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}
