/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.flowable.ui.modeler.serviceapi;

import org.flowable.idm.api.User;
import org.flowable.ui.modeler.model.AppDefinitionRepresentation;
import org.flowable.ui.modeler.model.AppDefinitionSaveRepresentation;
import org.flowable.ui.modeler.model.AppDefinitionUpdateResultRepresentation;

import java.util.List;

public interface AppDefinitionService {

    AppDefinitionRepresentation getAppDefinition(String appDefinitionId);

    AppDefinitionRepresentation getAppDefinitionHistory(String modelId, String modelHistoryId);

    AppDefinitionUpdateResultRepresentation updateAppDefinition(String modelId, AppDefinitionSaveRepresentation updatedModel);

    List<AppDefinitionServiceRepresentation> getAppDefinitions();

    List<AppDefinitionServiceRepresentation> getDeployableAppDefinitions(User user);

}