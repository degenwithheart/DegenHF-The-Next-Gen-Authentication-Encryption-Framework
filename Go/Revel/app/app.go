package app

import (
	"github.com/revel/revel/v3"
	"github.com/degenhf/DegenHF/Go/Revel/app/controllers"
	"github.com/degenhf/DegenHF/Go/Revel/app/models"
)

func init() {
	// Filters is the default set of global filters.
	revel.Filters = []revel.Filter{
		revel.PanicFilter,             // Recover from panics and display an error page instead.
		revel.RouterFilter,            // Use the routing table to select the right Action
		revel.FilterConfiguringFilter, // A hook for adding or removing per-Action filters.
		revel.ParamsFilter,            // Parse parameters into Controller.Params.
		revel.SessionFilter,           // Restore and write the session cookie.
		revel.FlashFilter,             // Restore and write the flash cookie.
		revel.ValidationFilter,        // Restore kept validation errors and save new ones from cookie.
		revel.I18nFilter,              // Resolve the requested language
		revel.InterceptorFilter,       // Run interceptors around the action.
		revel.CompressFilter,          // Compress the result.
		revel.BeforeAfterFilter,       // Call the before and after filter functions.
		revel.ActionInvoker,           // Invoke the action.
	}

	// Register startup functions with OnAppStart
	revel.OnAppStart(InitDB)
	revel.OnAppStart(InitAuthHandler)
}

// InitDB initializes the database connection
func InitDB() {
	// Initialize in-memory storage for demo
	// In production, replace with actual database
	models.InitStorage()
}

// InitAuthHandler initializes the ECC auth handler
func InitAuthHandler() {
	controllers.InitAuthHandler()
}