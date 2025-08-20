// Fix cancel buttons for all dialogs
document.addEventListener('DOMContentLoaded', function() {
  // Fix for create dialog cancel button
  const createDialog = document.getElementById('createDialog');
  const createCancelBtn = document.querySelector('#createDialog .btn-secondary');
  if (createCancelBtn && createCancelBtn.textContent === 'Cancel') {
    createCancelBtn.addEventListener('click', function() {
      createDialog.close();
    });
  }

  // Fix for edit dialog cancel button
  const editDialog = document.getElementById('editDialog');
  const editCancelBtn = document.querySelector('#editDialog .btn-secondary');
  if (editCancelBtn && editCancelBtn.textContent === 'Cancel') {
    editCancelBtn.addEventListener('click', function() {
      editDialog.close();
    });
  }

  // Fix for create reward dialog cancel button
  const createRewardDialog = document.getElementById('createRewardDialog');
  const createRewardCancelBtn = document.querySelector('#createRewardDialog .btn-secondary');
  if (createRewardCancelBtn && createRewardCancelBtn.textContent === 'Cancel') {
    createRewardCancelBtn.addEventListener('click', function() {
      createRewardDialog.close();
    });
  }

  // Fix for edit reward dialog cancel button
  const editRewardDialog = document.getElementById('editRewardDialog');
  const editRewardCancelBtn = document.querySelector('#editRewardDialog .btn-secondary');
  if (editRewardCancelBtn && editRewardCancelBtn.textContent === 'Cancel') {
    editRewardCancelBtn.addEventListener('click', function() {
      editRewardDialog.close();
    });
  }

  // Fix for confirm dialog cancel button
  const confirmDialog = document.getElementById('confirmDialog');
  const confirmCancelBtn = document.querySelector('#confirmDialog .btn-secondary');
  if (confirmCancelBtn && confirmCancelBtn.textContent === 'Cancel') {
    confirmCancelBtn.addEventListener('click', function() {
      confirmDialog.close();
    });
  }
});
