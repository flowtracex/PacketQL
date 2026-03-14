from repositories.base.usecase_repo import UseCaseRepository


class UseCaseService:
    def __init__(self):
        self.repo = UseCaseRepository()

    def list_usecases(self):
        return self.repo.list_usecases()

    def get_usecase(self, uc_id):
        return self.repo.get_usecase(uc_id)

    def list_signals(self):
        return self.repo.list_signals()

    def get_signal(self, sig_id):
        return self.repo.get_signal(sig_id)
