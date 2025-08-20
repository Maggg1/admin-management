// Comprehensive fix for cancel button validation issues
document.addEventListener('DOMContentLoaded', function() {
  // Fix all dialog cancel buttons to prevent form validation
  const dialogs = [
    { id: 'createDialog', form: 'createForm' },
    { id: 'editDialog', form: 'editForm' },
    { id: 'createRewardDialog', form: 'createRewardForm' },
    { id: 'editRewardDialog', form: 'editRewardForm' },
    { id: 'confirmDialog', form: null }
  ];

  dialogs.forEach(dialog => {
    const dialogEl = document.getElementById(dialog.id);
    const cancelBtn = dialogEl?.querySelector('.btn-secondary');
    
    if (cancelBtn) {
      // Remove existing event listeners by replacing the element
      const newCancelBtn = cancelBtn.cloneNode(true);
      cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
      
      // Add new event listener
      newCancelBtn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopImmediatePropagation();
        e.stopPropagation();
        
        // Close the dialog without validation
        dialogEl.close();
        
        // Reset form if it exists
        if (dialog.form) {
          const form = document.getElementById(dialog.form);
          if (form) {
            form.reset();
          }
        }
        
        return false;
      });
    }
  });

  // Also handle form submission to prevent validation on cancel
  const forms = ['createForm', 'editForm', 'createRewardForm', 'editRewardForm'];
  forms.forEach(formId => {
    const form = document.getElementById(formId);
    if (form) {
      form.addEventListener('submit', function(e) {
        const submitter = e.submitter;
        if (submitter && submitter.value === 'cancel') {
          e.preventDefault();
          const dialog = form.closest('dialog');
          if (dialog) {
            dialog.close();
          }
          return false;
        }
      });
    }
  });
});
